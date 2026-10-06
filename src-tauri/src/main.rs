// PhotoVault — password-locked, encrypted local photo & video library.
//
// Envelope encryption: a random 32-byte master key encrypts everything on
// disk (media, thumbnails, the index) with AES-256-GCM. The master key is
// wrapped by a KEK derived from the password via scrypt — so changing the
// password only re-wraps the master key — and optionally by a recovery key
// and a Touch ID-gated keychain item. The master key lives only in this
// process's memory while the vault is unlocked.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod native;
mod instance_lock;
mod backup;

use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::{Zeroize, Zeroizing};

const VERIFIER_PLAINTEXT: &[u8] = b"photovault-v1";
const DEFAULT_AUTO_LOCK_SECS: u64 = 15 * 60;
const THUMB_SIZE: u32 = 480;
const MIN_PASSWORD_LEN: usize = 8;
const TRASH_RETENTION_SECS: f64 = 30.0 * 86400.0;
const LEGACY_SCRYPT_LOG_N: u8 = 15;
const CURRENT_SCRYPT_LOG_N: u8 = 17;
const DEFAULT_SCRYPT_R: u32 = 8;
const DEFAULT_SCRYPT_P: u32 = 1;
const MAX_PHOTO_NAME_BYTES: usize = 255;
const HELPER_TIMEOUT: Duration = Duration::from_secs(20);
const INBOX_MIN_FILE_AGE: Duration = Duration::from_secs(2);
/// Hidden file naming the album for media in its Inbox folder (written when a zip is extracted).
const INBOX_ALBUM_MARKER: &str = ".photovault-album";
const UNZIP_STAGING_PREFIX: &str = ".photovault-unzip-";
const MAX_UNZIP_BYTES: u64 = 20 << 30;
const MAX_UNZIP_ENTRIES: usize = 100_000;
/// Objects are encrypted in one piece, so import holds the whole file in memory.
const MAX_IMPORT_BYTES: u64 = 4 << 30;
/// Nonce plus GCM tag that encryption adds to a plaintext.
const ENCRYPTION_OVERHEAD: usize = 12 + 16;

fn yes() -> bool {
    true
}
fn default_auto_lock() -> u64 {
    DEFAULT_AUTO_LOCK_SECS
}
fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    #[serde(default = "default_auto_lock")]
    auto_lock_secs: u64, // 0 = never
    #[serde(default = "yes")]
    skip_duplicates: bool,
    #[serde(default = "yes")]
    screen_protect: bool,
    #[serde(default = "yes")]
    lock_on_sleep: bool,
    #[serde(default)]
    touch_id: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
            skip_duplicates: true,
            screen_protect: true,
            lock_on_sleep: true,
            touch_id: false,
        }
    }
}

struct Vault {
    dir: PathBuf,
    // Watched folder: images saved here are pulled into the vault.
    inbox: PathBuf,
    key: Option<[u8; 32]>, // master key while unlocked
    // A generated recovery key the UI is showing, with its generation id. Only
    // written to meta once the user confirms that id, so the old key keeps
    // working until then. Cleared on lock.
    pending_recovery: Option<(String, Zeroizing<[u8; 32]>)>,
    // Changes on every unlock and wipe, so work that waited on a lock can tell
    // the vault was locked and unlocked again in the meantime.
    session: u64,
    // Set when a wipe locks the vault. Cleared once the UI knows: it asked for
    // the lock, got "locked" from vault_status, or got a vault-locked event.
    // lock_timer reports the rest, like an idle wipe inside a command.
    lock_unreported: bool,
    // Decrypted once at unlock and kept in memory; cleared on lock.
    photos: HashMap<String, PhotoInfo>,
    albums: HashMap<String, Album>,
    recovery_required: bool,
    last_activity: Instant,
    importing: bool,
    settings: Settings,
    // Serializes read-modify-write operations on meta.json without holding
    // the vault lock across the intentionally slow scrypt operation.
    meta_lock: Arc<Mutex<()>>,
    // Last decrypted full object, so video seeking doesn't re-decrypt the
    // whole file per range request. Cleared on lock.
    media_cache: Option<(String, Arc<Vec<u8>>)>,
    // Decrypted thumbnails (LRU, capped) so scrolling back through the grid
    // doesn't re-read and re-decrypt from disk. Cleared on lock.
    thumb_cache: HashMap<String, Arc<Vec<u8>>>,
    thumb_order: VecDeque<String>,
}

impl Vault {
    fn meta_path(&self) -> PathBuf {
        self.dir.join("meta.json")
    }
    /// Publishing meta is the last step of creating a vault. `read_meta` falls
    /// back to meta.bak, so either file means the vault exists.
    fn has_meta(&self) -> bool {
        self.meta_path().exists() || self.dir.join("meta.bak").exists()
    }
    fn index_path(&self) -> PathBuf {
        self.dir.join("index.enc")
    }
    fn index_bak_path(&self) -> PathBuf {
        self.dir.join("index.bak")
    }
    fn settings_path(&self) -> PathBuf {
        self.dir.join("settings.json")
    }
    fn objects_dir(&self) -> PathBuf {
        self.dir.join("objects")
    }

    /// Returns the master key if unlocked, auto-locking first when idle too long.
    /// Counts as user activity.
    fn active_key(&mut self) -> Option<[u8; 32]> {
        if self.idle_too_long() {
            wipe_vault(self);
        }
        if self.key.is_some() {
            self.last_activity = Instant::now();
        }
        self.key
    }

    /// The master key for background work, which isn't user activity. An idle
    /// vault reads as locked; lock_timer wipes it and tells the UI.
    fn background_key(&self) -> Option<[u8; 32]> {
        if self.idle_too_long() {
            None
        } else {
            self.key
        }
    }

    fn idle_too_long(&self) -> bool {
        self.key.is_some()
            && self.settings.auto_lock_secs > 0
            && !self.importing
            && self.last_activity.elapsed().as_secs() > self.settings.auto_lock_secs
    }
}

/// Clear all secrets and decrypted state from memory.
fn wipe_vault(vault: &mut Vault) {
    if let Some(k) = vault.key.as_mut() {
        k.zeroize();
        vault.lock_unreported = true;
    }
    vault.key = None;
    vault.session += 1;
    vault.pending_recovery = None;
    vault.photos.clear();
    vault.albums.clear();
    vault.media_cache = None;
    vault.thumb_cache.clear();
    vault.thumb_order.clear();
}

type VaultState<'a> = State<'a, Mutex<Vault>>;

/// Lock the vault mutex, recovering from poisoning (a panicked thread must
/// not brick the whole app — Vault state stays consistent either way).
fn vlock(m: &Mutex<Vault>) -> MutexGuard<'_, Vault> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn meta_lock(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    lock.lock().unwrap_or_else(|e| e.into_inner())
}

fn do_system_lock(app: &tauri::AppHandle) {
    let state: State<Mutex<Vault>> = app.state();
    let mut vault = vlock(&state);
    if vault.key.is_some() {
        wipe_vault(&mut vault);
        vault.lock_unreported = false;
        drop(vault);
        let _ = app.emit("vault-locked", ());
    }
}

#[derive(Serialize, Deserialize)]
struct Meta {
    salt: String,     // scrypt salt for the password KEK
    verifier: String, // encrypt(master, VERIFIER_PLAINTEXT)
    // Missing fields are the original v1 parameters. New writes use the
    // current parameters in rewrap_master, so old vaults remain readable.
    #[serde(default = "legacy_scrypt_log_n")]
    n: u8,
    #[serde(default = "default_scrypt_r")]
    r: u32,
    #[serde(default = "default_scrypt_p")]
    p: u32,
    // encrypt(kek, master). Absent = v1 layout (master derived directly
    // from the password); migrated in place on first unlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped_master: Option<String>,
    // encrypt(recovery_key_bytes, master)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<String>,
}

fn legacy_scrypt_log_n() -> u8 {
    LEGACY_SCRYPT_LOG_N
}

fn default_scrypt_r() -> u32 {
    DEFAULT_SCRYPT_R
}

fn default_scrypt_p() -> u32 {
    DEFAULT_SCRYPT_P
}

#[derive(Serialize, Deserialize, Clone)]
struct Album {
    name: String,
    created: f64,
}

#[derive(Serialize, Deserialize, Clone)]
struct PhotoInfo {
    name: String,
    added: f64,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    taken: Option<f64>, // EXIF capture date (or file date for videos)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hash: Option<String>, // BLAKE3 of plaintext; duplicate detection
    #[serde(default, skip_serializing_if = "is_false")]
    favorite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted: Option<f64>, // in trash since this timestamp
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    albums: Vec<String>, // album ids
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    height: Option<u32>,
}

#[derive(Default, Deserialize)]
struct IndexData {
    #[serde(default)]
    photos: HashMap<String, PhotoInfo>,
    #[serde(default)]
    albums: HashMap<String, Album>,
    #[serde(default)]
    recovery_required: bool,
}

#[derive(Serialize)]
struct IndexOut<'a> {
    photos: &'a HashMap<String, PhotoInfo>,
    albums: &'a HashMap<String, Album>,
    recovery_required: bool,
}

#[derive(Serialize)]
struct PhotoEntry {
    id: String,
    name: String,
    added: f64,
    size: Option<u64>,
    taken: Option<f64>,
    favorite: bool,
    deleted: Option<f64>,
    albums: Vec<String>,
    tags: Vec<String>,
    hash: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
}

#[derive(Serialize)]
struct AlbumEntry {
    id: String,
    name: String,
    created: f64,
}

// ---------------------------------------------------------------- crypto ---

fn derive_key_with_params(
    password: &str,
    salt: &[u8],
    n: u8,
    r: u32,
    p: u32,
) -> Result<[u8; 32], String> {
    let params = scrypt::Params::new(n, r, p, 32).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    derive_key_with_params(
        password,
        salt,
        LEGACY_SCRYPT_LOG_N,
        DEFAULT_SCRYPT_R,
        DEFAULT_SCRYPT_P,
    )
}

fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|e| e.to_string())?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(out)
}

fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 13 {
        return Err("corrupt blob".into());
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(&blob[..12]), &blob[12..])
        .map_err(|_| "decryption failed".to_string())
}

/// Same format as `encrypt`, but reuses `data`'s memory so a large original
/// isn't held twice. Reserve ENCRYPTION_OVERHEAD up front to avoid a realloc.
fn encrypt_owned(key: &[u8; 32], mut data: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    data.reserve_exact(ENCRYPTION_OVERHEAD);
    Aes256Gcm::new(key.into())
        .encrypt_in_place(Nonce::from_slice(&nonce), b"", &mut data)
        .map_err(|e| e.to_string())?;
    data.splice(..0, nonce);
    Ok(data)
}

/// `decrypt` that reuses the blob's memory for the plaintext.
fn decrypt_owned(key: &[u8; 32], mut blob: Vec<u8>) -> Result<Vec<u8>, String> {
    if blob.len() < 13 {
        return Err("corrupt blob".into());
    }
    let nonce: Vec<u8> = blob.drain(..12).collect();
    Aes256Gcm::new(key.into())
        .decrypt_in_place(Nonce::from_slice(&nonce), b"", &mut blob)
        .map_err(|_| "decryption failed".to_string())?;
    Ok(blob)
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn key_from_slice(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes.try_into().map_err(|_| "bad key length".to_string())
}

/// Format a recovery key for humans: 16 groups of 4 hex chars.
fn format_recovery_key(bytes: &[u8; 32]) -> String {
    hex::encode_upper(bytes)
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

fn parse_recovery_key(text: &str) -> Result<[u8; 32], String> {
    let cleaned: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let bytes = hex::decode(cleaned.to_lowercase())
        .map_err(|_| "That doesn't look like a recovery key.".to_string())?;
    key_from_slice(&bytes).map_err(|_| "That doesn't look like a recovery key.".to_string())
}

// ------------------------------------------------------------------ meta ---

fn read_meta_file(path: &std::path::Path) -> std::io::Result<Meta> {
    fs::read(path).and_then(|raw| serde_json::from_slice(&raw).map_err(std::io::Error::other))
}

fn read_meta(dir: &std::path::Path) -> Result<Meta, String> {
    match read_meta_file(&dir.join("meta.json")) {
        Ok(meta) => Ok(meta),
        Err(primary_err) => read_meta_file(&dir.join("meta.bak"))
            .map_err(|backup_err| format!("{primary_err}; backup: {backup_err}")),
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_DIRECTORY_SYNC: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static AFTER_INDEX_REPLACEMENT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static AFTER_SOURCE_CLAIM: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    // Once write_file_durably renames onto this path, its directory sync fails.
    static FAIL_SYNC_AFTER_REPLACING: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

fn sync_dir(dir: &std::path::Path) -> Result<(), String> {
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow().as_deref() == Some(dir)) {
        return Err("Simulated directory sync failure.".into());
    }
    fs::File::open(dir)
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())
}

/// A failed durable write. `Unconfirmed` means the new file already replaced
/// the old one, but the directory sync failed, so a crash might still undo it.
#[derive(Debug)]
enum WriteError {
    NotReplaced(String),
    Unconfirmed(String),
}

impl From<WriteError> for String {
    fn from(error: WriteError) -> String {
        match error {
            WriteError::NotReplaced(e) | WriteError::Unconfirmed(e) => e,
        }
    }
}

fn write_file_durably(
    tmp: &std::path::Path,
    dest: &std::path::Path,
    data: &[u8],
    dir: &std::path::Path,
) -> Result<(), WriteError> {
    let not_replaced = |e: std::io::Error| WriteError::NotReplaced(e.to_string());
    let mut file = fs::File::create(tmp).map_err(not_replaced)?;
    file.write_all(data).map_err(not_replaced)?;
    file.sync_all().map_err(not_replaced)?;
    drop(file);
    fs::rename(tmp, dest).map_err(not_replaced)?;
    #[cfg(test)]
    if FAIL_SYNC_AFTER_REPLACING.with(|path| path.borrow().as_deref() == Some(dest)) {
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(dir.to_path_buf()));
    }
    sync_dir(dir).map_err(WriteError::Unconfirmed)
}

/// Persist meta durably, without ever retaining a superseded wrapping.
///
/// `meta.bak` holds the *same* generation as `meta.json`, never the previous
/// one. The master key survives a password change (only its wrapping is
/// replaced), so an older meta — old salt plus old `wrapped_master` — would
/// let the old password recover the master key forever, and changing your
/// password would revoke nothing. That is the `meta.v1.bak` hole; rotating
/// generations here would simply recreate it on every password change, and
/// ship it to cloud storage inside every backup zip.
///
/// The backup is written first, so a crash mid-write leaves `meta.json`
/// authoritative and intact; once both renames land, neither file holds a
/// wrapping that a retired password can open.
///
/// `WriteError::Unconfirmed` means readers now see the new meta. Either
/// `meta.json` was replaced, or `meta.bak` was and `meta.json` isn't valid, so
/// `read_meta` falls back to the backup. Any other failure leaves the old
/// `meta.json` in charge, so it counts as not replaced.
fn write_meta(dir: &std::path::Path, meta: &Meta) -> Result<(), WriteError> {
    let json = serde_json::to_vec(meta).map_err(|e| WriteError::NotReplaced(e.to_string()))?;
    // Call once meta.bak holds the new meta but meta.json wasn't replaced.
    let backup_only = |e: String| match read_meta_file(&dir.join("meta.json")) {
        Ok(_) => WriteError::NotReplaced(e),
        Err(_) => WriteError::Unconfirmed(e),
    };
    match write_file_durably(
        &dir.join("meta.bak.tmp"),
        &dir.join("meta.bak"),
        &json,
        dir,
    ) {
        Ok(()) => {}
        Err(WriteError::Unconfirmed(e)) => return Err(backup_only(e)),
        Err(e) => return Err(e),
    }
    match write_file_durably(
        &dir.join("meta.json.tmp"),
        &dir.join("meta.json"),
        &json,
        dir,
    ) {
        Err(WriteError::NotReplaced(e)) => Err(backup_only(e)),
        result => result,
    }
}

fn remove_legacy_meta_backup(dir: &std::path::Path) {
    if fs::remove_file(dir.join("meta.v1.bak")).is_ok() {
        let _ = sync_dir(dir);
    }
}

/// Unwrap the master key with a password against the given meta.
/// Handles both the v2 envelope layout and the v1 direct-derivation layout.
fn master_from_password(password: &str, meta: &Meta) -> Result<[u8; 32], String> {
    let salt = hex::decode(&meta.salt).map_err(|e| e.to_string())?;
    let mut derived = derive_key_with_params(password, &salt, meta.n, meta.r, meta.p)?;
    let mut master = match &meta.wrapped_master {
        Some(wm) => {
            let blob = match hex::decode(wm) {
                Ok(blob) => blob,
                Err(e) => {
                    derived.zeroize();
                    return Err(e.to_string());
                }
            };
            let mut unwrapped = match decrypt(&derived, &blob) {
                Ok(unwrapped) => unwrapped,
                Err(_) => {
                    derived.zeroize();
                    return Err("Wrong password.".to_string());
                }
            };
            let result = key_from_slice(&unwrapped);
            unwrapped.zeroize();
            derived.zeroize();
            result?
        }
        None => derived, // v1: the derived key IS the master key
    };
    let verifier = match hex::decode(&meta.verifier) {
        Ok(verifier) => verifier,
        Err(e) => {
            master.zeroize();
            return Err(e.to_string());
        }
    };
    let mut plaintext = decrypt(&master, &verifier).unwrap_or_default();
    let valid = plaintext == VERIFIER_PLAINTEXT;
    plaintext.zeroize();
    if valid {
        Ok(master)
    } else {
        master.zeroize();
        Err("Wrong password.".into())
    }
}

/// Re-wrap the master key under a (new) password. Used by vault creation,
/// v1→v2 migration, password change, and recovery reset.
fn rewrap_master(meta: &mut Meta, password: &str, master: &[u8; 32]) -> Result<(), String> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut kek = derive_key_with_params(
        password,
        &salt,
        CURRENT_SCRYPT_LOG_N,
        DEFAULT_SCRYPT_R,
        DEFAULT_SCRYPT_P,
    )?;
    let wrapped = encrypt(&kek, master)?;
    kek.zeroize();
    meta.salt = hex::encode(salt);
    meta.n = CURRENT_SCRYPT_LOG_N;
    meta.r = DEFAULT_SCRYPT_R;
    meta.p = DEFAULT_SCRYPT_P;
    meta.wrapped_master = Some(hex::encode(wrapped));
    meta.verifier = hex::encode(encrypt(master, VERIFIER_PLAINTEXT)?);
    Ok(())
}

// ----------------------------------------------------------------- index ---

/// New format is a tagged object {photos, albums}; the legacy format was a
/// bare id→PhotoInfo map. Detect explicitly — deserializing legacy data into
/// the new struct would silently produce an empty library.
fn parse_index(json: &[u8]) -> Result<IndexData, String> {
    let val: serde_json::Value = serde_json::from_slice(json).map_err(|e| e.to_string())?;
    if val.get("photos").is_some() {
        serde_json::from_value(val).map_err(|e| e.to_string())
    } else {
        let photos: HashMap<String, PhotoInfo> =
            serde_json::from_value(val).map_err(|e| e.to_string())?;
        Ok(IndexData {
            photos,
            albums: HashMap::new(),
            recovery_required: false,
        })
    }
}

fn load_index(vault: &Vault, key: &[u8; 32]) -> Result<IndexData, String> {
    recover_index_transaction(vault, key)?;
    let read = |path: PathBuf| -> Result<IndexData, String> {
        let blob = fs::read(path).map_err(|e| e.to_string())?;
        parse_index(&decrypt(key, &blob)?)
    };
    let marker = vault.dir.join("recovery-required");
    let mut data = match read(vault.index_path()) {
        Ok(data) => data,
        Err(primary_error) => {
            let mut data = read(vault.index_bak_path()).map_err(|_| primary_error)?;
            data.recovery_required = true;
            data
        }
    };
    data.recovery_required |= marker.try_exists().map_err(|e| e.to_string())?;
    if data.recovery_required {
        // Record fallback before unlocking. A later save must never make
        // newer, unindexed objects look safe to delete after a restart.
        let file = fs::OpenOptions::new().write(true).create(true).truncate(false)
            .open(&marker).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        sync_dir(&vault.dir)?;
    }
    Ok(data)
}

/// Recover a save whose commit was interrupted. Keep the proposed generation for manual
/// recovery and disable automatic cleanup before restoring the last accepted generation.
fn recover_index_transaction(vault: &Vault, key: &[u8; 32]) -> Result<(), String> {
    let rollback = vault.dir.join("index.rollback");
    if !rollback.try_exists().map_err(|error| error.to_string())? {
        return Ok(());
    }
    let previous = fs::read(&rollback).map_err(|error| error.to_string())?;
    parse_index(&decrypt(key, &previous)?)?;
    if let Ok(proposed) = fs::read(vault.index_path()) {
        if proposed != previous {
            // Preserve metadata for newly imported objects even if a crash resurrected
            // the journal after an acknowledged commit. Existing recovery backups stay intact.
            let saved = unique_dest(&vault.dir, "index.unconfirmed");
            write_object(&saved, &proposed)?;
        }
    }
    let marker = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(vault.dir.join("recovery-required"))
        .map_err(|error| error.to_string())?;
    marker.sync_all().map_err(|error| error.to_string())?;
    sync_dir(&vault.dir)?;
    let recovery = vault.dir.join("index.recovery.tmp");
    let mut file = fs::File::create(&recovery).map_err(|error| error.to_string())?;
    file.write_all(&previous)
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    fs::rename(recovery, vault.index_path()).map_err(|error| error.to_string())?;
    sync_dir(&vault.dir)?;
    fs::remove_file(&rollback).map_err(|error| error.to_string())?;
    // The restored index and recovery marker are already durable. A failed sync
    // here may repeat recovery after a crash, but cannot expose the proposed index.
    let _ = sync_dir(&vault.dir);
    Ok(())
}

/// Keep a durable previous generation until the new index and its directory entry
/// are synced. Any error retains index.rollback, which loading handles before index.enc.
fn persist_index(vault: &Vault, key: &[u8; 32]) -> Result<(), String> {
    let rollback = vault.dir.join("index.rollback");
    if rollback.try_exists().map_err(|error| error.to_string())? {
        return Err("An earlier library save was interrupted. Lock and unlock the vault to recover it before making more changes.".into());
    }
    let previous = if vault
        .index_path()
        .try_exists()
        .map_err(|error| error.to_string())?
        || vault
            .index_bak_path()
            .try_exists()
            .map_err(|error| error.to_string())?
    {
        load_index(vault, key)?
    } else {
        IndexData::default()
    };
    let prior = IndexOut {
        photos: &previous.photos,
        albums: &previous.albums,
        recovery_required: previous.recovery_required,
    };
    let previous_blob = encrypt(
        key,
        &serde_json::to_vec(&prior).map_err(|error| error.to_string())?,
    )?;
    let out = IndexOut {
        photos: &vault.photos,
        albums: &vault.albums,
        recovery_required: vault.recovery_required,
    };
    let json = serde_json::to_vec(&out).map_err(|e| e.to_string())?;
    let blob = encrypt(key, &json)?;
    let tmp = vault.index_path().with_extension("tmp");
    let mut file = fs::File::create(&tmp).map_err(|e| e.to_string())?;
    file.write_all(&blob).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    let rollback_tmp = vault.dir.join("index.rollback.tmp");
    let mut file = fs::File::create(&rollback_tmp).map_err(|error| error.to_string())?;
    file.write_all(&previous_blob)
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    fs::rename(rollback_tmp, &rollback).map_err(|error| error.to_string())?;
    sync_dir(&vault.dir)?;
    let commit = || -> Result<(), String> {
        if !vault.recovery_required
            && vault
                .index_path()
                .try_exists()
                .map_err(|error| error.to_string())?
        {
            fs::rename(vault.index_path(), vault.index_bak_path())
                .map_err(|error| error.to_string())?;
        }
        fs::rename(tmp, vault.index_path()).map_err(|e| e.to_string())?;
        #[cfg(test)]
        AFTER_INDEX_REPLACEMENT.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        sync_dir(&vault.dir)?;
        fs::remove_file(&rollback).map_err(|error| error.to_string())?;
        Ok(())
    };
    if let Err(error) = commit() {
        return Err(format!("Library save was interrupted: {error}. The previous index is retained; lock and unlock to recover it."));
    }
    // The new index is already durable. Do not turn a journal-cleanup sync failure
    // into a failed mutation after removing the only rollback reference.
    let _ = sync_dir(&vault.dir);
    Ok(())
}

/// Write to a temp file and rename it over settings.json, so a failed write
/// leaves the old settings intact. An error means the old file is still in
/// place. Once the rename lands the new file is the one a restart reads, so a
/// failed directory sync after it counts as saved and callers keep the new values.
fn save_settings(vault: &Vault) -> Result<(), String> {
    match write_file_durably(
        &vault.dir.join("settings.json.tmp"),
        &vault.settings_path(),
        &serde_json::to_vec(&vault.settings).map_err(|e| e.to_string())?,
        &vault.dir,
    ) {
        Ok(()) | Err(WriteError::Unconfirmed(_)) => Ok(()),
        Err(WriteError::NotReplaced(e)) => Err(e),
    }
}

/// Load the index into memory and mark the vault unlocked. Also purges
/// photos that have been in the trash longer than the retention window.
fn finish_unlock(state: &Mutex<Vault>, master: [u8; 32]) -> Result<(), String> {
    let mut vault = vlock(state);
    let data = load_index(&vault, &master)?;
    vault.photos = data.photos;
    vault.albums = data.albums;
    vault.recovery_required = data.recovery_required;
    let cutoff = now_secs() - TRASH_RETENTION_SECS;
    let expired: Vec<String> = vault
        .photos
        .iter()
        .filter(|(_, p)| !vault.recovery_required && p.deleted.map_or(false, |d| d < cutoff))
        .map(|(id, _)| id.clone())
        .collect();
    let expired_blobs: Vec<PathBuf> = expired
        .iter()
        .flat_map(|id| {
            [
                vault.objects_dir().join(id),
                vault.objects_dir().join(format!("{id}.t")),
            ]
        })
        .collect();
    let mut removed = Vec::new();
    for id in &expired {
        removed.extend(vault.photos.remove_entry(id));
        vault.media_cache = vault
            .media_cache
            .take()
            .filter(|(cached_id, _)| !expired.contains(cached_id));
        vault
            .thumb_cache
            .retain(|cached_id, _| !expired.contains(cached_id));
        vault
            .thumb_order
            .retain(|cached_id| !expired.contains(cached_id));
    }
    if !expired.is_empty() {
        // Expiry is housekeeping. If it can't be saved, keep the items until
        // the next unlock rather than refuse to open the vault.
        match persist_index(&vault, &master) {
            Ok(()) => {
                for path in expired_blobs {
                    let _ = fs::remove_file(path);
                }
            }
            Err(_) => vault.photos.extend(removed),
        }
    }
    vault.key = Some(master);
    vault.session += 1;
    vault.last_activity = Instant::now();
    Ok(())
}

// ---------------------------------------------------------------- images ---

const IMAGE_EXTS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "tif", "heic", "heif",
];
const VIDEO_EXTS: &[&str] = &["mp4", "mov", "m4v"];

fn ext_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, e)) => e.to_lowercase(),
        None => String::new(),
    }
}

fn is_video_name(name: &str) -> bool {
    VIDEO_EXTS.contains(&ext_of(name).as_str())
}

fn is_media_path(path: &std::path::Path) -> bool {
    path.extension()
        .map(|e| {
            let e = e.to_string_lossy().to_lowercase();
            IMAGE_EXTS.contains(&e.as_str()) || VIDEO_EXTS.contains(&e.as_str())
        })
        .unwrap_or(false)
}

fn is_zip_path(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("zip"))
}

fn is_hidden(path: &std::path::Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy().starts_with('.'))
        .unwrap_or(true)
}

fn exif_orientation(data: &[u8]) -> u32 {
    let mut cursor = std::io::Cursor::new(data);
    exif::Reader::new()
        .read_from_container(&mut cursor)
        .ok()
        .and_then(|e| {
            e.get_field(exif::Tag::Orientation, exif::In::PRIMARY)
                .and_then(|f| f.value.get_uint(0))
        })
        .unwrap_or(1)
}

fn apply_orientation(img: image::DynamicImage, o: u32) -> image::DynamicImage {
    match o {
        2 => img.fliph(),
        3 => img.rotate180(),
        4 => img.flipv(),
        5 => img.rotate90().fliph(),
        6 => img.rotate90(),
        7 => img.rotate270().fliph(),
        8 => img.rotate270(),
        _ => img,
    }
}

/// Days-from-civil (Howard Hinnant) — EXIF timestamps to epoch seconds
/// without a date-time dependency. EXIF times are zoneless local time;
/// treated as UTC, which is fine for sorting.
fn civil_to_epoch(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> f64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    (days * 86400 + hh * 3600 + mm * 60 + ss) as f64
}

/// Capture date from EXIF (works for JPEG, TIFF, HEIC containers).
fn exif_taken(data: &[u8]) -> Option<f64> {
    let mut cursor = std::io::Cursor::new(data);
    let reader = exif::Reader::new().read_from_container(&mut cursor).ok()?;
    for tag in [
        exif::Tag::DateTimeOriginal,
        exif::Tag::DateTimeDigitized,
        exif::Tag::DateTime,
    ] {
        let Some(field) = reader.get_field(tag, exif::In::PRIMARY) else {
            continue;
        };
        let exif::Value::Ascii(ref vals) = field.value else {
            continue;
        };
        let Some(bytes) = vals.first() else { continue };
        let Ok(dt) = exif::DateTime::from_ascii(bytes) else {
            continue;
        };
        let mut t = civil_to_epoch(
            dt.year as i64,
            dt.month as i64,
            dt.day as i64,
            dt.hour as i64,
            dt.minute as i64,
            dt.second as i64,
        );
        if let Some(offset_min) = dt.offset {
            t -= offset_min as f64 * 60.0;
        }
        return Some(t);
    }
    None
}

fn encode_thumb(img: &image::DynamicImage) -> Option<Vec<u8>> {
    let mut out = std::io::Cursor::new(Vec::new());
    img.thumbnail(THUMB_SIZE, THUMB_SIZE)
        .to_rgb8()
        .write_to(&mut out, image::ImageFormat::Jpeg)
        .ok()?;
    Some(out.into_inner())
}

/// Run a macOS helper without allowing a hung QuickLook or image conversion
/// process to wedge the import worker forever.
fn command_status_with_timeout(
    mut command: std::process::Command,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let mut child = command.spawn().ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Convert an image the decoder can't read (HEIC from iPhones) to JPEG using
/// macOS's built-in `sips`. The source is already plaintext on disk, so the
/// short-lived plaintext conversion in the private temp dir doesn't weaken
/// the at-rest story.
fn sips_to_jpeg(src: &std::path::Path) -> Result<Vec<u8>, ImportFailure> {
    let dir = std::env::temp_dir().join(format!("pv-conv-{}", random_id()));
    fs::create_dir_all(&dir).map_err(ImportFailure::temporary)?;
    let out = dir.join("converted.jpg");
    let mut command = std::process::Command::new("/usr/bin/sips");
    command
        .args(["-s", "format", "jpeg", "--"])
        .arg(src)
        .arg("--out")
        .arg(&out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let bytes = converted_image_output(command_status_with_timeout(command, HELPER_TIMEOUT), &out);
    let _ = fs::remove_dir_all(&dir);
    bytes
}

// A helper exit code does not distinguish invalid media from an output I/O failure.
fn converted_image_output(
    status: Option<std::process::ExitStatus>,
    output: &std::path::Path,
) -> Result<Vec<u8>, ImportFailure> {
    match status {
        Some(status) if status.success() => fs::read(output).map_err(ImportFailure::temporary),
        None => Err(ImportFailure::temporary(
            "Image conversion could not start or timed out.",
        )),
        Some(status) => Err(ImportFailure::temporary(format!(
            "Image conversion failed ({status})."
        ))),
    }
}

/// Poster frame for a video via QuickLook's thumbnailer.
fn video_thumbnail(src: &std::path::Path) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("pv-thumb-{}", random_id()));
    fs::create_dir_all(&dir).ok()?;
    let mut command = std::process::Command::new("/usr/bin/qlmanage");
    command
        .args(["-t", "-s", "960", "-o"])
        .arg(&dir)
        .arg("--")
        .arg(src)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = command_status_with_timeout(command, HELPER_TIMEOUT);
    let mut png = None;
    if matches!(status, Some(s) if s.success()) {
        if let Ok(entries) = fs::read_dir(&dir) {
            png = entries
                .flatten()
                .map(|e| e.path())
                .find(|p| p.extension().map_or(false, |e| e == "png"))
                .and_then(|p| fs::read(p).ok());
        }
    }
    let _ = fs::remove_dir_all(&dir);
    let img = image::load_from_memory(&png?).ok()?;
    encode_thumb(&img)
}

fn placeholder_thumb() -> Vec<u8> {
    let img = image::RgbImage::from_pixel(THUMB_SIZE, THUMB_SIZE, image::Rgb([26, 26, 33]));
    let mut out = std::io::Cursor::new(Vec::new());
    let _ = image::DynamicImage::ImageRgb8(img).write_to(&mut out, image::ImageFormat::Jpeg);
    out.into_inner()
}

struct MediaMeta {
    thumb: Vec<u8>,
    width: Option<u32>,
    height: Option<u32>,
    taken: Option<f64>,
}

/// Decode, orient, and thumbnail one media file; extract capture date and
/// dimensions along the way. Conversion I/O and timeouts remain retryable.
fn prepare_media(path: &std::path::Path, data: &[u8]) -> Result<MediaMeta, ImportFailure> {
    if is_media_path(path)
        && is_video_name(
            &path
                .file_name()
                .ok_or_else(|| ImportFailure::temporary("Source has no filename."))?
                .to_string_lossy(),
        )
    {
        let thumb = video_thumbnail(path).unwrap_or_else(placeholder_thumb);
        let taken = fs::metadata(path)
            .ok()
            .and_then(|m| m.created().or_else(|_| m.modified()).ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64());
        return Ok(MediaMeta {
            thumb,
            width: None,
            height: None,
            taken,
        });
    }
    let (img, converted) = match image::load_from_memory(data) {
        Ok(img) => (img, None),
        Err(_) => {
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            // These formats have recognizable signatures. HEIC/HEIF still need the native decoder.
            if matches!(
                extension.as_str(),
                "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "tif" | "tiff"
            ) && image::guess_format(data).is_err()
            {
                return Err(ImportFailure::permanent(
                    "File contents are not a supported image.",
                ));
            }
            let jpg = sips_to_jpeg(path)?;
            let img = image::load_from_memory(&jpg).map_err(|e| {
                ImportFailure::temporary(format!("Cannot read converted image: {e}"))
            })?;
            (img, Some(jpg))
        }
    };
    let orient_src: &[u8] = converted.as_deref().unwrap_or(data);
    let img = apply_orientation(img, exif_orientation(orient_src));
    let (width, height) = (img.width(), img.height());
    let thumb =
        encode_thumb(&img).ok_or_else(|| ImportFailure::temporary("Cannot encode thumbnail."))?;
    let taken = exif_taken(data).or_else(|| converted.as_deref().and_then(exif_taken));
    Ok(MediaMeta {
        thumb,
        width: Some(width),
        height: Some(height),
        taken,
    })
}

/// One run of a name. Digit runs compare numerically (by digit count then
/// lexically, so arbitrarily long runs work without parsing into an integer);
/// everything else compares case-insensitively. Numbers sort before text,
/// matching how Finder orders a folder.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NamePart {
    Number(usize, String, String),
    Text(String),
}

fn name_key(s: &str) -> Vec<NamePart> {
    let mut parts = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut digits = String::new();
            while chars.peek().map_or(false, |c| c.is_ascii_digit()) {
                digits.push(chars.next().unwrap());
            }
            let significant = digits.trim_start_matches('0');
            parts.push(NamePart::Number(
                significant.len(),
                significant.to_string(),
                digits,
            ));
        } else {
            let mut text = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_digit() {
                    break;
                }
                text.extend(c.to_lowercase());
                chars.next();
            }
            parts.push(NamePart::Text(text));
        }
    }
    parts
}

/// Import order is the order the files read in a file browser: components
/// compared one level at a time so a folder's contents stay together, each
/// naturally (`IMG_2` before `IMG_10`). The path itself breaks ties that
/// case-folding creates, so the order never depends on `read_dir`.
fn path_sort_key(path: &std::path::Path) -> (Vec<Vec<NamePart>>, PathBuf) {
    let parts = path
        .components()
        .map(|c| name_key(&c.as_os_str().to_string_lossy()))
        .collect();
    (parts, path.to_path_buf())
}

fn sort_paths_by_name(paths: &mut [PathBuf]) {
    paths.sort_by_cached_key(|path| path_sort_key(path));
}

/// Expand files and folders into a flat list of media-file paths.
/// Folders are walked recursively; hidden entries are skipped.

fn collect_files(paths: &[String], result: &mut ImportResult) -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, depth: u32, out: &mut Vec<PathBuf>, result: &mut ImportResult) {
        if depth > 8 {
            result.issue(
                dir,
                "Folder exceeds the supported nesting depth.".into(),
                "import",
                false,
            );
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                result.issue(dir, e.to_string(), "import", true);
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    result.issue(dir, e.to_string(), "import", true);
                    continue;
                }
            };
            let path = entry.path();
            if is_hidden(&path) {
                continue;
            }
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    result.issue(&path, e.to_string(), "import", true);
                    continue;
                }
            };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                walk(&path, depth + 1, out, result);
            } else if ft.is_file() && is_media_path(&path) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    for p in paths {
        let path = PathBuf::from(p);
        let ft = match fs::symlink_metadata(&path).map(|m| m.file_type()) {
            Ok(ft) => ft,
            Err(e) => {
                result.issue(&path, e.to_string(), "import", true);
                continue;
            }
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk(&path, 0, &mut out, result);
        } else if ft.is_file() {
            out.push(path); // direct files: let the decoder decide
        }
    }
    // The same path can appear twice (e.g. a file selected alongside its
    // parent folder) — import each actual file once per import action.
    let mut unique = HashSet::new();
    out.retain(|p| unique.insert(p.clone()));
    sort_paths_by_name(&mut out);
    out
}

// ---------------------------------------------------------- auth commands ---

#[tauri::command]
async fn vault_status(state: VaultState<'_>) -> Result<String, String> {
    let mut vault = vlock(&state);
    Ok(if !vault.has_meta() {
        "new".into()
    } else if vault.active_key().is_some() {
        "unlocked".into()
    } else {
        // The UI shows the lock screen for this answer, so lock_timer doesn't
        // need to report the lock again and reset the login form.
        vault.lock_unreported = false;
        "locked".into()
    })
}

#[tauri::command]
async fn recovery_status(state: VaultState<'_>) -> Result<bool, String> {
    let mut vault = vlock(&state);
    vault.active_key().ok_or("locked")?;
    Ok(vault.recovery_required)
}

#[derive(Serialize)]
struct LockScreenInfo {
    has_recovery: bool,
    touch_id: bool,
    inbox_pending: usize,
}

/// Everything the lock/login screen needs, callable while locked.
#[tauri::command]
async fn lock_screen_info(state: VaultState<'_>) -> Result<LockScreenInfo, String> {
    let (dir, inbox, touch_id_setting) = {
        let vault = vlock(&state);
        (
            vault.dir.clone(),
            vault.inbox.clone(),
            vault.settings.touch_id,
        )
    };
    let has_recovery = read_meta(&dir)
        .map(|m| m.recovery.is_some())
        .unwrap_or(false);
    let inbox_pending = {
        let mut found = Vec::new();
        scan_inbox_media(&inbox, 0, &mut found);
        found.len()
    };
    Ok(LockScreenInfo {
        has_recovery,
        touch_id: touch_id_setting && native::biometrics_available(),
        inbox_pending,
    })
}

#[tauri::command]
async fn create_vault(password: String, state: VaultState<'_>) -> Result<(), String> {
    create_new_vault(&state, &password)
}

fn create_new_vault(state: &Mutex<Vault>, password: &str) -> Result<(), String> {
    let meta_mutex = vlock(state).meta_lock.clone();
    let _meta_guard = meta_lock(&meta_mutex);
    if vlock(state).has_meta() {
        return Err("Vault already exists.".into());
    }
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters."
        ));
    }
    let master = random_key();
    let mut meta = Meta {
        salt: String::new(),
        verifier: String::new(),
        n: LEGACY_SCRYPT_LOG_N,
        r: DEFAULT_SCRYPT_R,
        p: DEFAULT_SCRYPT_P,
        wrapped_master: None,
        recovery: None,
    };
    rewrap_master(&mut meta, password, &master)?; // slow (scrypt): outside the lock
    let mut vault = vlock(state);
    fs::create_dir_all(vault.objects_dir()).map_err(|e| e.to_string())?;
    // An earlier failed attempt may have left an index under its own master
    // key. Without meta nothing can open it, so start over.
    for name in ["index.enc", "index.bak", "index.rollback", "recovery-required"] {
        match fs::remove_file(vault.dir.join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
    }
    vault.photos = HashMap::new();
    vault.albums = HashMap::new();
    persist_index(&vault, &master)?;
    // Meta goes last, so the vault only exists once it's complete. If readers
    // see the new meta, the vault is done even if the disk didn't confirm it.
    match write_meta(&vault.dir, &meta) {
        Ok(()) | Err(WriteError::Unconfirmed(_)) => {}
        Err(WriteError::NotReplaced(e)) => return Err(e),
    }
    vault.key = Some(master);
    vault.session += 1;
    vault.last_activity = Instant::now();
    Ok(())
}

#[tauri::command]
async fn unlock(password: String, state: VaultState<'_>) -> Result<(), String> {
    unlock_with_password(&state, &password)
}

fn unlock_with_password(state: &Mutex<Vault>, password: &str) -> Result<(), String> {
    let (dir, meta_mutex) = {
        let vault = vlock(state);
        (vault.dir.clone(), vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    let meta = read_meta(&dir)?;
    let master = match master_from_password(password, &meta) {
        Ok(m) => m,
        Err(e) => {
            std::thread::sleep(Duration::from_millis(500));
            return Err(e);
        }
    };
    // Seamless v1 → v2 migration: wrap the existing key as the master key.
    if meta.wrapped_master.is_none() {
        let mut meta = meta;
        rewrap_master(&mut meta, password, &master)?;
        match write_meta(&dir, &meta) {
            // Readers see the new meta, and the same password opens it.
            Ok(()) | Err(WriteError::Unconfirmed(_)) => {}
            Err(WriteError::NotReplaced(e)) => return Err(e),
        }
    }
    remove_legacy_meta_backup(&dir);
    finish_unlock(state, master)
}

/// What a credential change returns. `warning` is set when the change took
/// effect but the disk didn't confirm the write, so a crash might undo it.
#[derive(Serialize)]
struct Saved {
    warning: Option<String>,
}

/// Write meta for a credential change. An error means nothing changed. Once
/// readers see the new meta the change counts, with `warning` if unconfirmed.
fn save_meta(dir: &std::path::Path, meta: &Meta, warning: &str) -> Result<Saved, String> {
    match write_meta(dir, meta) {
        Ok(()) => Ok(Saved { warning: None }),
        Err(WriteError::Unconfirmed(_)) => Ok(Saved { warning: Some(warning.into()) }),
        Err(WriteError::NotReplaced(e)) => Err(e),
    }
}

#[tauri::command]
async fn change_password(
    current_password: String,
    new_password: String,
    state: VaultState<'_>,
) -> Result<Saved, String> {
    change_vault_password(&state, &current_password, &new_password)
}

fn change_vault_password(
    state: &Mutex<Vault>,
    current_password: &str,
    new_password: &str,
) -> Result<Saved, String> {
    if new_password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "New password must be at least {MIN_PASSWORD_LEN} characters."
        ));
    }
    let (dir, master, meta_mutex) = {
        let mut vault = vlock(state);
        let key = vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), key, vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    if vlock(state).active_key() != Some(master) {
        return Err("The vault changed or locked. Try again after unlocking.".into());
    }
    let mut meta = read_meta(&dir)?;
    master_from_password(current_password, &meta)
        .map_err(|_| "Current password is incorrect.".to_string())?;
    rewrap_master(&mut meta, new_password, &master)?;
    let saved = save_meta(
        &dir,
        &meta,
        "Password changed, but the disk didn't confirm the write. Use your new password from now on. Keep the old one until you've unlocked once with the new one.",
    )?;
    remove_legacy_meta_backup(&dir);
    Ok(saved)
}

#[derive(Serialize)]
struct NewRecoveryKey {
    key: String,
    // Pass back to recovery_confirm, so Done saves the key that was shown.
    id: String,
}

/// Generate a new recovery key and return it formatted for humans. It's only
/// held in memory until `recovery_confirm` saves it, so the old key keeps
/// working if the vault locks or the UI never shows this one.
#[tauri::command]
async fn recovery_generate(state: VaultState<'_>) -> Result<NewRecoveryKey, String> {
    generate_recovery_key(&state)
}

fn generate_recovery_key(state: &Mutex<Vault>) -> Result<NewRecoveryKey, String> {
    let mut vault = vlock(state);
    vault.active_key().ok_or("locked")?;
    let rk = Zeroizing::new(random_key());
    let shown = NewRecoveryKey {
        key: format_recovery_key(&rk),
        id: random_id(),
    };
    vault.pending_recovery = Some((shown.id.clone(), rk));
    Ok(shown)
}

/// Save the key from `recovery_generate` with this id once the user has seen
/// it. This replaces the old recovery key. An error means nothing changed.
#[tauri::command]
async fn recovery_confirm(id: String, state: VaultState<'_>) -> Result<Saved, String> {
    confirm_recovery_key(&state, &id)
}

fn confirm_recovery_key(state: &Mutex<Vault>, id: &str) -> Result<Saved, String> {
    let (dir, master, session, meta_mutex) = {
        let mut vault = vlock(state);
        let key = vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), key, vault.session, vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    let rk = {
        let mut vault = vlock(state);
        // Unlocking restores the same master key, so only the session shows
        // a lock and unlock while this waited for the meta lock.
        if vault.active_key().is_none() || vault.session != session {
            return Err("The vault changed or locked. Try again after unlocking.".into());
        }
        match &vault.pending_recovery {
            Some((pending_id, rk)) if pending_id == id => rk.clone(),
            _ => return Err("This recovery key is no longer waiting to be saved. Generate a new one.".into()),
        }
    };
    let mut meta = read_meta(&dir)?;
    meta.recovery = Some(hex::encode(encrypt(&rk, &master)?));
    // The new key works now, but a crash could still bring back the old one.
    let saved = save_meta(
        &dir,
        &meta,
        "Saved, but the disk didn't confirm the write. Keep this new key, and keep any old key until you've unlocked once with the new one.",
    )?;
    // Keep a newer key generated while this one was being saved.
    let mut vault = vlock(state);
    if vault.pending_recovery.as_ref().is_some_and(|(pending_id, _)| pending_id == id) {
        vault.pending_recovery = None;
    }
    Ok(saved)
}

#[tauri::command]
async fn recovery_disable(state: VaultState<'_>) -> Result<Saved, String> {
    disable_recovery_key(&state)
}

fn disable_recovery_key(state: &Mutex<Vault>) -> Result<Saved, String> {
    let (dir, master, meta_mutex) = {
        let mut vault = vlock(state);
        let master = vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), master, vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    {
        let mut vault = vlock(state);
        if vault.active_key() != Some(master) {
            return Err("The vault changed or locked. Try again after unlocking.".into());
        }
        vault.pending_recovery = None;
    }
    let mut meta = read_meta(&dir)?;
    meta.recovery = None;
    let saved = save_meta(
        &dir,
        &meta,
        "Recovery key turned off, but the disk didn't confirm the write. If it shows as set up after a restart, turn it off again.",
    )?;
    remove_legacy_meta_backup(&dir);
    Ok(saved)
}

/// Forgot-password path: the recovery key unwraps the master key, and the
/// vault password is reset in the same step.
#[tauri::command]
async fn recovery_unlock(
    recovery_key: String,
    new_password: String,
    state: VaultState<'_>,
) -> Result<Saved, String> {
    unlock_with_recovery_key(&recovery_key, &new_password, &state)
}

fn unlock_with_recovery_key(
    recovery_key: &str,
    new_password: &str,
    state: &Mutex<Vault>,
) -> Result<Saved, String> {
    if new_password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "New password must be at least {MIN_PASSWORD_LEN} characters."
        ));
    }
    let rk = parse_recovery_key(recovery_key)?;
    let (dir, meta_mutex) = {
        let vault = vlock(state);
        (vault.dir.clone(), vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    let mut meta = read_meta(&dir)?;
    let wrapped = meta
        .recovery
        .clone()
        .ok_or("No recovery key is set up for this vault.")?;
    let blob = hex::decode(&wrapped).map_err(|e| e.to_string())?;
    let mut master_bytes = match decrypt(&rk, &blob) {
        Ok(m) => m,
        Err(_) => {
            std::thread::sleep(Duration::from_millis(500));
            return Err("Wrong recovery key.".into());
        }
    };
    let master = match key_from_slice(&master_bytes) {
        Ok(m) => {
            master_bytes.zeroize();
            m
        }
        Err(_) => {
            master_bytes.zeroize();
            return Err("Wrong recovery key.".into());
        }
    };
    let verifier = hex::decode(&meta.verifier).map_err(|e| e.to_string())?;
    let mut plaintext = decrypt(&master, &verifier).unwrap_or_default();
    let valid = plaintext == VERIFIER_PLAINTEXT;
    plaintext.zeroize();
    if !valid {
        return Err("Wrong recovery key.".into());
    }
    rewrap_master(&mut meta, new_password, &master)?;
    // Once the new password works, finish unlocking even if the disk didn't confirm it.
    let saved = save_meta(
        &dir,
        &meta,
        "Password reset, but the disk didn't confirm the write. Use your new password from now on. Keep your recovery key, too.",
    )?;
    remove_legacy_meta_backup(&dir);
    finish_unlock(state, master)?;
    Ok(saved)
}

// ---------------------------------------------------------------- Touch ID ---

#[tauri::command]
async fn touchid_available() -> Result<bool, String> {
    Ok(native::biometrics_available())
}

#[tauri::command]
async fn touchid_enable(state: VaultState<'_>) -> Result<(), String> {
    let master = {
        let mut vault = vlock(&state);
        vault.active_key().ok_or("locked")?
    };
    if !native::biometrics_available() {
        return Err("Touch ID isn't available on this Mac.".into());
    }
    native::authenticate_biometric("enable Touch ID unlock for PhotoVault")?;
    native::keychain_store_master(&master)?;
    let mut vault = vlock(&state);
    let previous = std::mem::replace(&mut vault.settings.touch_id, true);
    if let Err(e) = save_settings(&vault) {
        vault.settings.touch_id = previous;
        if !previous {
            // Don't leave a usable copy of the master key behind a setting that's off.
            native::keychain_delete_master();
        }
        return Err(e);
    }
    Ok(())
}

#[tauri::command]
async fn touchid_disable(state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let previous = std::mem::replace(&mut vault.settings.touch_id, false);
    if let Err(e) = save_settings(&vault) {
        // The key stays too, so Touch ID unlock still works with the setting on.
        vault.settings.touch_id = previous;
        return Err(e);
    }
    drop(vault);
    native::keychain_delete_master();
    Ok(())
}

#[tauri::command]
async fn touchid_unlock(state: VaultState<'_>) -> Result<(), String> {
    let (dir, enabled) = {
        let vault = vlock(&state);
        (vault.dir.clone(), vault.settings.touch_id)
    };
    if !enabled {
        return Err("Touch ID unlock isn't enabled.".into());
    }
    // Biometric prompt + keychain read happen without holding the vault lock.
    native::authenticate_biometric("unlock your photo vault")?;
    let bytes = native::keychain_read_master()?;
    let master = key_from_slice(&bytes)?;
    let meta_mutex = vlock(&state).meta_lock.clone();
    let _meta_guard = meta_lock(&meta_mutex);
    let meta = read_meta(&dir)?;
    let verifier = hex::decode(&meta.verifier).map_err(|e| e.to_string())?;
    match decrypt(&master, &verifier) {
        Ok(pt) if pt == VERIFIER_PLAINTEXT => finish_unlock(&state, master),
        _ => Err(
            "The stored Touch ID key no longer matches this vault — re-enable it in Settings."
                .into(),
        ),
    }
}

// ------------------------------------------------------- session commands ---

/// UI signals user interaction (throttled) so the vault doesn't auto-lock
/// while someone is actively looking at photos without issuing commands.
/// An idle vault locks here instead of reviving, like any other user command.
#[tauri::command]
async fn touch_activity(state: VaultState<'_>) -> Result<(), String> {
    vlock(&state).active_key();
    Ok(())
}

#[tauri::command]
async fn get_settings(state: VaultState<'_>) -> Result<Settings, String> {
    Ok(vlock(&state).settings.clone())
}

#[derive(Serialize)]
struct BuildInfo {
    version: String,
    build: &'static str,
}

#[tauri::command]
fn get_build_info(app: tauri::AppHandle) -> BuildInfo {
    BuildInfo {
        version: app.package_info().version.to_string(),
        build: env!("PHOTOVAULT_BUILD_ID"),
    }
}

#[tauri::command]
async fn set_settings(
    settings: Settings,
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<(), String> {
    {
        let mut vault = vlock(&state);
        // touch_id is managed by its own commands (keychain side effects).
        let touch_id = vault.settings.touch_id;
        let previous = std::mem::replace(
            &mut vault.settings,
            Settings {
                touch_id,
                ..settings
            },
        );
        vault.last_activity = Instant::now();
        if let Err(e) = save_settings(&vault) {
            vault.settings = previous;
            return Err(e);
        }
    }
    if let Some(window) = app.get_webview_window("main") {
        let protect = vlock(&state).settings.screen_protect;
        native::set_screen_protect(&window, protect);
    }
    Ok(())
}

/// Proactively enforce the auto-lock so the UI flips to the login screen the
/// moment the timeout expires, and lock when the machine slept while we
/// weren't watching (wall-clock jump — belt to the notification suspenders).
fn lock_timer(app: tauri::AppHandle) {
    let mut prev_wall = SystemTime::now();
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let wall = SystemTime::now();
        let slept = wall
            .duration_since(prev_wall)
            .map(|d| d.as_secs() > 90)
            .unwrap_or(false);
        prev_wall = wall;
        let state: State<Mutex<Vault>> = app.state();
        let mut vault = vlock(&state);
        if lock_tick(&mut vault, slept) {
            drop(vault);
            let _ = app.emit("vault-locked", ());
        }
    }
}

/// One lock_timer pass. Returns true when the UI needs a vault-locked event:
/// this pass locked the vault, or something else wiped it without telling the
/// UI (a command that found it idle).
fn lock_tick(vault: &mut Vault, slept: bool) -> bool {
    if vault.idle_too_long() || (vault.key.is_some() && slept && vault.settings.lock_on_sleep) {
        wipe_vault(vault);
    }
    std::mem::take(&mut vault.lock_unreported) && vault.key.is_none()
}

#[tauri::command]
async fn lock(state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    wipe_vault(&mut vault);
    vault.lock_unreported = false; // the UI asked for it
    Ok(())
}

// --------------------------------------------------------- photo commands ---

#[tauri::command]
async fn list_photos(state: VaultState<'_>) -> Result<Vec<PhotoEntry>, String> {
    photo_list(&state)
}

// The UI also reloads the lists after every Inbox pass, so reading them isn't
// user activity. An idle vault reads as locked until lock_timer locks it.
fn photo_list(state: &Mutex<Vault>) -> Result<Vec<PhotoEntry>, String> {
    let vault = vlock(state);
    vault.background_key().ok_or("locked")?;
    Ok(vault
        .photos
        .iter()
        .map(|(id, p)| PhotoEntry {
            id: id.clone(),
            name: p.name.clone(),
            added: p.added,
            size: p.size,
            taken: p.taken,
            favorite: p.favorite,
            deleted: p.deleted,
            albums: p.albums.clone(),
            tags: p.tags.clone(),
            hash: p.hash.clone(),
            width: p.width,
            height: p.height,
        })
        .collect())
}

#[tauri::command]
async fn list_albums(state: VaultState<'_>) -> Result<Vec<AlbumEntry>, String> {
    album_list(&state)
}

fn album_list(state: &Mutex<Vault>) -> Result<Vec<AlbumEntry>, String> {
    let vault = vlock(state);
    vault.background_key().ok_or("locked")?;
    let mut albums: Vec<AlbumEntry> = vault
        .albums
        .iter()
        .map(|(id, a)| AlbumEntry {
            id: id.clone(),
            name: a.name.clone(),
            created: a.created,
        })
        .collect();
    albums.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(albums)
}

/// Apply `edit` to the in-memory library and save it. If either step fails, photos
/// and albums go back to how they were, so a later save can't persist a change
/// the user was told failed.
fn edit_library<T>(
    vault: &mut Vault,
    key: &[u8; 32],
    edit: impl FnOnce(&mut Vault) -> Result<T, String>,
) -> Result<T, String> {
    let photos = vault.photos.clone();
    let albums = vault.albums.clone();
    let saved = edit(vault).and_then(|out| persist_index(vault, key).map(|()| out));
    if saved.is_err() {
        vault.photos = photos;
        vault.albums = albums;
    }
    saved
}

#[tauri::command]
async fn album_create(name: String, state: VaultState<'_>) -> Result<String, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Album name can't be empty.".into());
    }
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    create_album(&mut vault, &key, name)
}

fn create_album(vault: &mut Vault, key: &[u8; 32], name: String) -> Result<String, String> {
    edit_library(vault, key, |vault| {
        let id = random_id();
        vault.albums.insert(
            id.clone(),
            Album {
                name,
                created: now_secs(),
            },
        );
        Ok(id)
    })
}

#[tauri::command]
async fn album_rename(id: String, name: String, state: VaultState<'_>) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Album name can't be empty.".into());
    }
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    edit_library(&mut vault, &key, |vault| {
        vault.albums.get_mut(&id).ok_or("Album not found.")?.name = name;
        Ok(())
    })
}

#[tauri::command]
async fn album_delete(id: String, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    delete_album(&mut vault, &key, &id)
}

fn delete_album(vault: &mut Vault, key: &[u8; 32], id: &str) -> Result<(), String> {
    if !vault.albums.contains_key(id) {
        return Ok(());
    }
    edit_library(vault, key, |vault| {
        vault.albums.remove(id);
        for p in vault.photos.values_mut() {
            p.albums.retain(|a| a != id);
        }
        Ok(())
    })
}

#[tauri::command]
async fn albums_assign(
    ids: Vec<String>,
    album: String,
    add: bool,
    state: VaultState<'_>,
) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    assign_album(&mut vault, &key, &ids, &album, add)
}

fn assign_album(
    vault: &mut Vault,
    key: &[u8; 32],
    ids: &[String],
    album: &str,
    add: bool,
) -> Result<(), String> {
    if !vault.albums.contains_key(album) {
        return Err("Album not found.".into());
    }
    edit_library(vault, key, |vault| {
        for id in ids {
            if let Some(p) = vault.photos.get_mut(id) {
                if add && !p.albums.iter().any(|a| a == album) {
                    p.albums.push(album.to_string());
                } else if !add {
                    p.albums.retain(|a| a != album);
                }
            }
        }
        Ok(())
    })
}

#[tauri::command]
async fn set_favorite(
    ids: Vec<String>,
    favorite: bool,
    state: VaultState<'_>,
) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    mark_favorite(&mut vault, &key, &ids, favorite)
}

fn mark_favorite(
    vault: &mut Vault,
    key: &[u8; 32],
    ids: &[String],
    favorite: bool,
) -> Result<(), String> {
    edit_library(vault, key, |vault| {
        for id in ids {
            if let Some(p) = vault.photos.get_mut(id) {
                p.favorite = favorite;
            }
        }
        Ok(())
    })
}

#[tauri::command]
async fn rename_photo(id: String, name: String, state: VaultState<'_>) -> Result<(), String> {
    let name = sanitize_photo_name(&name)?;
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    edit_library(&mut vault, &key, |vault| {
        vault.photos.get_mut(&id).ok_or("not found")?.name = name;
        Ok(())
    })
}

/// Trim, drop empties, dedupe case-insensitively keeping the first spelling.
fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for t in tags {
        let t = t.trim().to_string();
        if !t.is_empty() && seen.insert(t.to_lowercase()) {
            out.push(t);
        }
    }
    out
}

#[tauri::command]
async fn set_tags(id: String, tags: Vec<String>, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    set_photo_tags(&mut vault, &key, &id, tags)
}

fn set_photo_tags(
    vault: &mut Vault,
    key: &[u8; 32],
    id: &str,
    tags: Vec<String>,
) -> Result<(), String> {
    edit_library(vault, key, |vault| {
        vault.photos.get_mut(id).ok_or("not found")?.tags = normalize_tags(tags);
        Ok(())
    })
}

// ----------------------------------------------------------------- import ---

#[derive(Serialize, Clone)]
struct ImportProgress {
    done: usize,
    total: usize,
}

#[derive(Serialize, Clone, Default)]
struct ImportResult {
    imported: usize,
    skipped: usize,
    failed: usize,
    cleanup_failed: usize,
    issues: Vec<ImportIssue>,
}

#[derive(Serialize, Clone)]
struct ImportIssue {
    name: String,
    reason: String,
    stage: &'static str,
    retryable: bool,
    #[serde(skip)]
    retry_path: Option<PathBuf>,
    #[serde(skip)]
    slow_retry: bool,
}

impl ImportResult {
    fn issue(
        &mut self,
        path: &std::path::Path,
        reason: String,
        stage: &'static str,
        retryable: bool,
    ) {
        if stage == "cleanup" {
            self.cleanup_failed += 1;
        } else {
            self.failed += 1;
        }
        self.issues.push(ImportIssue {
            name: path.to_string_lossy().into_owned(),
            reason,
            stage,
            retryable,
            retry_path: None,
            slow_retry: false,
        });
    }
}

#[derive(Debug)]
struct ImportFailure {
    reason: String,
    retryable: bool,
    /// Retry only after a long wait, like a full disk that needs the user's attention.
    slow_retry: bool,
}

impl ImportFailure {
    fn temporary(reason: impl ToString) -> Self {
        Self {
            reason: reason.to_string(),
            retryable: true,
            slow_retry: false,
        }
    }

    fn permanent(reason: impl ToString) -> Self {
        Self {
            reason: reason.to_string(),
            retryable: false,
            slow_retry: false,
        }
    }
}

/// Identity and content belong to the same open file that supplied the imported bytes.
struct SourceProof {
    metadata: fs::Metadata,
    hash: blake3::Hash,
}

fn same_source(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return false;
        }
    }
    a.is_file() && b.is_file() && a.len() == b.len() && a.modified().ok() == b.modified().ok()
}

/// Read the whole source, with room left to encrypt it in place.
fn read_source(path: &std::path::Path) -> Result<(Vec<u8>, SourceProof), ImportFailure> {
    let mut data = Vec::new();
    let proof = scan_source(path, |file, len| {
        data = read_capped(file, len)?;
        Ok(blake3::hash(&data))
    })?;
    Ok((data, proof))
}

/// Read at most `len` bytes, the size checked against the import cap. A file
/// that grew since then fails instead of being read past the cap.
fn read_capped(file: &mut impl Read, len: u64) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(len as usize + ENCRYPTION_OVERHEAD)
        .map_err(|_| std::io::Error::other("Not enough memory to import this file."))?;
    file.take(len + 1).read_to_end(&mut data)?;
    if data.len() as u64 > len {
        return Err(std::io::Error::other(
            "Source changed while it was being read.",
        ));
    }
    Ok(data)
}

/// Same checks and hash as `read_source`, streamed so the file isn't loaded again.
fn hash_source(path: &std::path::Path) -> Result<SourceProof, ImportFailure> {
    scan_source(path, |file, _| hash_file(file))
}

/// Streaming blake3 of the rest of an open file.
fn hash_file(file: &mut fs::File) -> std::io::Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    std::io::copy(file, &mut hasher)?;
    Ok(hasher.finalize())
}

fn scan_source(
    path: &std::path::Path,
    hash: impl FnOnce(&mut fs::File, u64) -> std::io::Result<blake3::Hash>,
) -> Result<SourceProof, ImportFailure> {
    let before = fs::symlink_metadata(path).map_err(ImportFailure::temporary)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(ImportFailure::temporary(
            "Source is no longer a regular file.",
        ));
    }
    let mut file = fs::File::open(path).map_err(ImportFailure::temporary)?;
    let metadata = file.metadata().map_err(ImportFailure::temporary)?;
    if !same_source(&before, &metadata) {
        return Err(ImportFailure::temporary(
            "Source changed before it could be read.",
        ));
    }
    // Checked before reading. Permanent, so the Inbox doesn't retry it every minute.
    if metadata.len() > MAX_IMPORT_BYTES {
        return Err(ImportFailure::permanent(
            "File is larger than 4 GB, which PhotoVault can't import yet.",
        ));
    }
    let hash = hash(&mut file, metadata.len()).map_err(ImportFailure::temporary)?;
    if file_signature(&metadata)
        != file_signature(&file.metadata().map_err(ImportFailure::temporary)?)
    {
        return Err(ImportFailure::temporary(
            "Source changed while it was being read.",
        ));
    }
    Ok(SourceProof { metadata, hash })
}

struct ImportGuard<'a> {
    state: &'a Mutex<Vault>,
}

impl Drop for ImportGuard<'_> {
    fn drop(&mut self) {
        vlock(self.state).importing = false;
    }
}

fn claim_import<'a>(state: &'a Mutex<Vault>) -> Result<ImportGuard<'a>, String> {
    claim_import_as(state, true)
}

/// The Inbox watcher's claim. It doesn't count as activity, so retrying a file
/// that keeps failing can't hold the vault open past auto-lock.
fn claim_background_import<'a>(state: &'a Mutex<Vault>) -> Result<ImportGuard<'a>, String> {
    claim_import_as(state, false)
}

fn claim_import_as<'a>(state: &'a Mutex<Vault>, user: bool) -> Result<ImportGuard<'a>, String> {
    let mut vault = vlock(state);
    let key = if user {
        vault.active_key()
    } else {
        vault.background_key()
    };
    key.ok_or("locked")?;
    if vault.importing {
        return Err("An import is already running.".into());
    }
    vault.importing = true;
    Ok(ImportGuard { state })
}

fn skipped_target_is_live(state: &Mutex<Vault>, id: &str) -> bool {
    let vault = vlock(state);
    vault
        .photos
        .get(id)
        .is_some_and(|photo| photo.deleted.is_none())
}

enum ImportOutcome {
    Added(String, PhotoInfo, SourceProof),
    /// A byte-identical copy is already in the vault; carries its photo id so
    /// an album-targeted import can still file the existing copy.
    Skipped(String, SourceProof),
    Failed(ImportFailure),
}

/// Merge a batch of imported photos into the index and persist it.
fn flush_batch(state: &Mutex<Vault>, batch: &mut Vec<(String, PhotoInfo)>) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut vault = vlock(state);
    // Re-check the key: the vault may have been locked mid-import. No activity
    // bump: `importing` already holds off auto-lock while the import runs.
    let key = vault.key.ok_or("locked")?;
    let ids: Vec<String> = batch.iter().map(|(id, _)| id.clone()).collect();
    for (id, mut info) in batch.drain(..) {
        // The target album can be deleted while a long import runs — never
        // persist a photo pointing at an album that no longer exists.
        info.albums.retain(|a| vault.albums.contains_key(a));
        vault.photos.insert(id, info);
    }
    // Roll back on a failed persist: entries living only in memory would
    // satisfy later duplicate checks even though nothing reached disk.
    if let Err(e) = persist_index(&vault, &key) {
        for id in &ids {
            vault.photos.remove(id);
        }
        return Err(e);
    }
    Ok(())
}

fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    fs::create_dir(path)
}

fn delete_inbox_source(
    inbox: &std::path::Path,
    path: &std::path::Path,
    proof: &SourceProof,
    retained: &mut Option<PathBuf>,
) -> Result<(), String> {
    claim_and_remove(inbox, path, retained, |claimed| {
        let current = hash_source(claimed).map_err(|e| e.reason)?;
        if !same_source(&proof.metadata, &current.metadata) || proof.hash != current.hash {
            return Err("Source changed after it was read; the changed file was preserved.".into());
        }
        Ok(())
    })
}

/// Rename first so replacing the original pathname cannot make cleanup delete the replacement.
/// A crash or changed source leaves the claimed file in a visible, automatically scanned folder.
/// `verify` checks the claimed file is still the one that was imported.
fn claim_and_remove(
    inbox: &std::path::Path,
    path: &std::path::Path,
    retained: &mut Option<PathBuf>,
    verify: impl FnOnce(&std::path::Path) -> Result<(), String>,
) -> Result<(), String> {
    let parent = path.parent().ok_or("Source has no parent directory.")?;
    let claimed_dir = inbox.join(format!("Pending import {}", random_id()));
    create_private_dir(&claimed_dir).map_err(|e| e.to_string())?;
    let claimed = claimed_dir.join(path.file_name().ok_or("Source has no filename.")?);
    if let Err(e) = fs::rename(path, &claimed) {
        let _ = fs::remove_dir(&claimed_dir);
        return Err(e.to_string());
    }
    *retained = Some(claimed.clone());
    #[cfg(test)]
    AFTER_SOURCE_CLAIM.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let cleanup = || -> Result<(), String> {
        // Persist the recovery name before doing anything that could remove it.
        sync_dir(&claimed_dir)?;
        sync_dir(inbox)?;
        sync_dir(parent)?;
        verify(&claimed)?;
        fs::remove_file(&claimed).map_err(|e| e.to_string())?;
        sync_dir(&claimed_dir)?;
        Ok(())
    };
    if let Err(e) = cleanup() {
        return Err(if claimed.exists() {
            format!("{e} Original retained at {}.", claimed.display())
        } else {
            e
        });
    }
    *retained = None;
    let _ = fs::remove_dir(&claimed_dir);
    prune_empty_dirs(inbox, parent);
    Ok(())
}

fn write_object(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

/// Encrypt one file into the vault objects dir. `hashes` maps the content
/// hashes already in the vault (and this batch) to their photo ids, for
/// duplicate skipping.
fn import_one(
    key: &[u8; 32],
    objects: &std::path::Path,
    path: &std::path::Path,
    hashes: &mut HashMap<String, String>,
    skip_dups: bool,
) -> ImportOutcome {
    let (data, proof) = match read_source(path) {
        Ok(source) => source,
        Err(e) => return ImportOutcome::Failed(e),
    };
    let hash = proof.hash.to_hex().to_string();
    if skip_dups {
        if let Some(existing) = hashes.get(&hash) {
            return ImportOutcome::Skipped(existing.clone(), proof);
        }
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "photo".into());
    let media = prepare_media(path, &data);
    // Native media helpers use the pathname; reject a changed source before saving their output.
    match hash_source(path) {
        Ok(current)
            if same_source(&proof.metadata, &current.metadata) && proof.hash == current.hash => {}
        _ => {
            return ImportOutcome::Failed(ImportFailure::temporary(
                "Source changed while preparing media.",
            ))
        }
    }
    let media = match media {
        Ok(media) => media,
        Err(e) => return ImportOutcome::Failed(e),
    };
    let size = data.len() as u64;
    let (Ok(enc), Ok(enc_thumb)) = (encrypt_owned(key, data), encrypt(key, &media.thumb)) else {
        return ImportOutcome::Failed(ImportFailure::temporary("Could not encrypt media."));
    };
    let id = random_id();
    let original = objects.join(&id);
    let thumb = objects.join(format!("{id}.t"));
    let persisted = write_object(&original, &enc)
        .and_then(|_| write_object(&thumb, &enc_thumb))
        .and_then(|_| sync_dir(objects));
    if let Err(e) = persisted {
        let _ = fs::remove_file(&original);
        let _ = fs::remove_file(&thumb);
        return ImportOutcome::Failed(ImportFailure::temporary(format!(
            "Cannot save encrypted media: {e}"
        )));
    }
    hashes.insert(hash.clone(), id.clone());
    ImportOutcome::Added(
        id,
        PhotoInfo {
            name,
            added: now_secs(),
            size: Some(size),
            taken: media.taken,
            hash: Some(hash),
            favorite: false,
            deleted: None,
            albums: Vec::new(),
            tags: Vec::new(),
            width: media.width,
            height: media.height,
        },
        proof,
    )
}

/// Content hashes eligible for duplicate skipping, mapped to the photo that
/// holds each one. Trashed photos don't count — they're on a purge timer, so a
/// re-import must create a fresh copy rather than being "skipped" into
/// eventual data loss.
fn existing_hashes(vault: &Vault) -> HashMap<String, String> {
    vault
        .photos
        .iter()
        .filter(|(_, p)| p.deleted.is_none())
        .filter_map(|(id, p)| p.hash.clone().map(|hash| (hash, id.clone())))
        .collect()
}

/// File photos already in the vault into an album — the duplicates an
/// album-targeted import skipped. Dropping a photo you already own onto an
/// album should still put it in that album.
fn file_existing_into_album(
    state: &Mutex<Vault>,
    ids: &[String],
    album: &str,
) -> Result<(), String> {
    let mut vault = vlock(state);
    let key = vault.key.ok_or("locked")?;
    // The album can be deleted while a long import runs.
    if !vault.albums.contains_key(album) {
        return Ok(());
    }
    let original_albums: Vec<_> = ids
        .iter()
        .filter_map(|id| {
            vault
                .photos
                .get(id)
                .map(|photo| (id.clone(), photo.albums.clone()))
        })
        .collect();
    for id in ids {
        if let Some(p) = vault.photos.get_mut(id) {
            if !p.albums.iter().any(|a| a == album) {
                p.albums.push(album.to_string());
            }
        }
    }
    if let Err(e) = persist_index(&vault, &key) {
        for (id, albums) in original_albums {
            if let Some(photo) = vault.photos.get_mut(&id) {
                photo.albums = albums;
            }
        }
        return Err(e);
    }
    Ok(())
}

fn run_import(
    files: Vec<PathBuf>,
    key: [u8; 32],
    objects: PathBuf,
    mut hashes: HashMap<String, String>,
    skip_dups: bool,
    album: Option<String>,
    mut progress: impl FnMut(ImportProgress),
    state: &Mutex<Vault>,
) -> Result<ImportResult, String> {
    let total = files.len();
    let mut batch: Vec<(String, PhotoInfo)> = Vec::new();
    let mut dup_files: Vec<(String, PathBuf)> = Vec::new();
    let mut result = ImportResult::default();
    let mut pending = Vec::new();
    let commit = |batch: &mut Vec<(String, PhotoInfo)>,
                  pending: &mut Vec<PathBuf>,
                  result: &mut ImportResult| {
        match flush_batch(&*state, batch) {
            Ok(()) => {
                result.imported += pending.len();
                pending.clear();
                true
            }
            Err(e) => {
                // A lock failure leaves the batch intact; do not retry files already reported as failed.
                batch.clear();
                for path in pending.drain(..) {
                    result.issue(
                        &path,
                        format!("Could not save library index: {e}"),
                        "import",
                        true,
                    );
                }
                false
            }
        }
    };
    for (i, path) in files.iter().enumerate() {
        if i % 25 == 0 {
            progress(ImportProgress { done: i, total });
        }
        match import_one(&key, &objects, path, &mut hashes, skip_dups) {
            ImportOutcome::Added(id, mut info, _) => {
                if let Some(album) = &album {
                    info.albums.push(album.clone());
                }
                batch.push((id, info));
                pending.push(path.clone());
                if batch.len() >= 100 && !commit(&mut batch, &mut pending, &mut result) {
                    for path in &files[i + 1..] {
                        result.issue(
                            path,
                            "Not attempted because the index could not be saved.".into(),
                            "import",
                            true,
                        );
                    }
                    break;
                }
            }
            ImportOutcome::Skipped(existing, _) => {
                // Count duplicates only after the source entry has reached the index.
                if batch.iter().any(|(id, _)| id == &existing)
                    && !commit(&mut batch, &mut pending, &mut result)
                {
                    for path in &files[i..] {
                        result.issue(
                            path,
                            "Not imported because the index could not be saved.".into(),
                            "import",
                            true,
                        );
                    }
                    break;
                }
                result.skipped += 1;
                if album.is_some() {
                    dup_files.push((existing, path.clone()));
                }
            }
            ImportOutcome::Failed(e) => result.issue(path, e.reason, "import", e.retryable),
        }
    }
    commit(&mut batch, &mut pending, &mut result);
    if let Some(album) = &album {
        if !dup_files.is_empty() {
            let ids: Vec<_> = dup_files.iter().map(|(id, _)| id.clone()).collect();
            if let Err(e) = file_existing_into_album(&*state, &ids, album) {
                for (_, path) in dup_files {
                    result.skipped -= 1;
                    result.issue(
                        &path,
                        format!("Could not add existing photo to album: {e}"),
                        "import",
                        true,
                    );
                }
            }
        }
    }
    progress(ImportProgress { done: total, total });
    Ok(result)
}

/// Import files/folders into the library, or straight into `album` when the
/// drop targeted one.
#[tauri::command]
async fn import_photos(
    paths: Vec<String>,
    album: Option<String>,
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<ImportResult, String> {
    let (key, objects, hashes, skip_dups) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        // Checked before claiming the import lock so a bad album id can't
        // leave `importing` stuck on.
        if album
            .as_ref()
            .is_some_and(|a| !vault.albums.contains_key(a))
        {
            return Err("Album not found.".into());
        }
        (
            key,
            vault.objects_dir(),
            existing_hashes(&vault),
            vault.settings.skip_duplicates,
        )
    };
    let _import_guard = claim_import(&*state)?;
    // Heavy work (decode + encrypt) happens outside the mutex.
    let mut discovery = ImportResult::default();
    let files = collect_files(&paths, &mut discovery);
    let mut result = run_import(
        files,
        key,
        objects,
        hashes,
        skip_dups,
        album,
        |progress| { let _ = app.emit("import-progress", progress); },
        &state,
    )?;
    result.failed += discovery.failed;
    result.issues.extend(discovery.issues);
    Ok(result)
}

/// Sweep orphaned object files (e.g. from an import that crashed before
/// writing its index). Never touches anything referenced by the index.
#[tauri::command]
async fn cleanup_orphans(state: VaultState<'_>) -> Result<usize, String> {
    let mut vault = vlock(&state);
    vault.active_key().ok_or("locked")?;
    Ok(sweep_orphans(&vault))
}

fn sweep_orphans(vault: &Vault) -> usize {
    if vault.importing || vault.recovery_required {
        return 0;
    }
    let mut removed = 0usize;
    if let Ok(entries) = fs::read_dir(vault.objects_dir()) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().into_owned();
            let base = fname.strip_suffix(".t").unwrap_or(&fname);
            if !vault.photos.contains_key(base) {
                let _ = fs::remove_file(entry.path());
                removed += 1;
            }
        }
    }
    removed
}

// ------------------------------------------------------------------ trash ---

#[tauri::command]
async fn trash_photos(ids: Vec<String>, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    if vault.importing {
        return Err("An import is running — wait for it to finish.".into());
    }
    set_deleted(&mut vault, &key, &ids, Some(now_secs()))
}

#[tauri::command]
async fn restore_photos(ids: Vec<String>, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    set_deleted(&mut vault, &key, &ids, None)
}

fn set_deleted(
    vault: &mut Vault,
    key: &[u8; 32],
    ids: &[String],
    deleted: Option<f64>,
) -> Result<(), String> {
    let original: Vec<_> = ids
        .iter()
        .filter_map(|id| {
            vault
                .photos
                .get(id)
                .map(|photo| (id.clone(), photo.deleted))
        })
        .collect();
    for id in ids {
        if let Some(photo) = vault.photos.get_mut(id) {
            photo.deleted = deleted;
        }
    }
    if let Err(error) = persist_index(vault, key) {
        for (id, deleted) in original {
            if let Some(photo) = vault.photos.get_mut(&id) {
                photo.deleted = deleted;
            }
        }
        return Err(error);
    }
    Ok(())
}

/// Permanently delete (from the trash, or anywhere).
#[tauri::command]
async fn purge_photos(ids: Vec<String>, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    if vault.importing {
        return Err("An import is running — wait for it to finish.".into());
    }
    let mut changed = false;
    let mut removed: Vec<(String, PhotoInfo)> = Vec::new();
    for id in &ids {
        if let Some(photo) = vault.photos.remove(id) {
            changed = true;
            removed.push((id.clone(), photo));
        }
    }
    if changed {
        if let Some((cid, _)) = &vault.media_cache {
            if ids.contains(cid) {
                vault.media_cache = None;
            }
        }
        for id in &ids {
            vault.thumb_cache.remove(id);
        }
        vault.thumb_order.retain(|id| !ids.contains(id));
        if let Err(e) = persist_index(&vault, &key) {
            for (id, photo) in removed {
                vault.photos.insert(id, photo);
            }
            return Err(e);
        }
        for id in &ids {
            let _ = fs::remove_file(vault.objects_dir().join(id));
            let _ = fs::remove_file(vault.objects_dir().join(format!("{id}.t")));
        }
    }
    Ok(())
}

#[tauri::command]
async fn empty_trash(state: VaultState<'_>) -> Result<usize, String> {
    let ids: Vec<String> = {
        let mut vault = vlock(&state);
        vault.active_key().ok_or("locked")?;
        if vault.importing {
            return Err("An import is running — wait for it to finish.".into());
        }
        vault
            .photos
            .iter()
            .filter(|(_, p)| p.deleted.is_some())
            .map(|(id, _)| id.clone())
            .collect()
    };
    let n = ids.len();
    purge_photos(ids, state).await?;
    Ok(n)
}

#[tauri::command]
async fn clear_vault(state: VaultState<'_>) -> Result<usize, String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    if vault.importing {
        return Err("An import is running — wait for it to finish.".into());
    }
    clear_vault_contents(&mut vault, &key)
}

fn clear_vault_contents(vault: &mut Vault, key: &[u8; 32]) -> Result<usize, String> {
    let photos = std::mem::take(&mut vault.photos);
    let albums = std::mem::take(&mut vault.albums);
    let count = photos.len();
    if let Err(error) = persist_index(vault, key) {
        vault.photos = photos;
        vault.albums = albums;
        return Err(error);
    }
    vault.media_cache = None;
    vault.thumb_cache.clear();
    vault.thumb_order.clear();
    if let Ok(entries) = fs::read_dir(vault.objects_dir()) {
        for entry in entries.flatten() {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(count)
}

// ----------------------------------------------------------------- export ---

/// A destination path in `dir` for `name` that doesn't collide:
/// "photo.jpg", then "photo (1).jpg", "photo (2).jpg", …
fn unique_dest(dir: &std::path::Path, name: &str) -> PathBuf {
    let safe_name = std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && *n != "." && *n != ".." && !n.contains('\0'))
        .unwrap_or("photo");
    let first = dir.join(safe_name);
    if fs::symlink_metadata(&first).is_err() {
        return first;
    }
    let (stem, ext) = match safe_name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (safe_name.to_string(), String::new()),
    };
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| fs::symlink_metadata(p).is_err())
        .unwrap()
}

fn sanitize_photo_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > MAX_PHOTO_NAME_BYTES
        || name.starts_with('.')
        || name.starts_with('-')
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(
            "Name must be a safe filename (1–255 bytes, without separators or a leading dot/dash)."
                .into(),
        );
    }
    Ok(name.to_string())
}

#[tauri::command]
async fn export_photo(id: String, dest: String, state: VaultState<'_>) -> Result<(), String> {
    let (key, path) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        if !vault.photos.contains_key(&id) {
            return Err("not found".into());
        }
        (key, vault.objects_dir().join(&id))
    };
    let blob = fs::read(path).map_err(|e| e.to_string())?;
    let data = decrypt_owned(&key, blob)?;
    fs::write(dest, data).map_err(|e| e.to_string())
}

#[derive(Serialize, Default)]
struct ExportResult {
    exported: usize,
    failed: usize,
    issues: Vec<ExportIssue>,
}

#[derive(Serialize)]
struct ExportIssue {
    name: String,
    reason: String,
}

impl ExportResult {
    fn failed(&mut self, name: String, reason: String) {
        self.failed += 1;
        self.issues.push(ExportIssue { name, reason });
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_EXPORT_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Reserve the output atomically so an export cannot overwrite a file created after its name check.
fn write_export(dir: &std::path::Path, name: &str, data: &[u8]) -> Result<(), String> {
    let (path, mut file) = loop {
        let path = unique_dest(dir, name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => break (path, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("Cannot create exported file: {error}")),
        }
    };
    let mut write = || -> std::io::Result<()> {
        #[cfg(test)]
        if FAIL_EXPORT_WRITE.with(|fail| fail.replace(false)) {
            file.write_all(&data[..data.len().min(1)])?;
            return Err(std::io::Error::other(
                "Simulated failure after a partial export write.",
            ));
        }
        file.write_all(data).and_then(|_| file.sync_all())
    };
    write().map_err(|error| {
        format!("Cannot finish exported file at {}: {error}. Check this destination for incomplete output before retrying.", path.display())
    })?;
    Ok(())
}

fn export_entries(
    key: &[u8; 32],
    objects: &std::path::Path,
    dir: &std::path::Path,
    entries: &[(String, String)],
    mut result: ExportResult,
    mut progress: impl FnMut(ImportProgress),
) -> ExportResult {
    let directory = fs::create_dir_all(dir);
    let total = entries.len() + result.failed;
    let already_failed = result.failed;
    for (i, (id, name)) in entries.iter().enumerate() {
        if i % 25 == 0 {
            progress(ImportProgress {
                done: i + already_failed,
                total,
            });
        }
        let exported = || -> Result<(), String> {
            if let Err(error) = &directory {
                return Err(format!("Cannot open export folder: {error}"));
            }
            let blob = fs::read(objects.join(id))
                .map_err(|error| format!("Cannot read encrypted original: {error}"))?;
            let data = decrypt_owned(key, blob)
                .map_err(|error| format!("Cannot decrypt original: {error}"))?;
            write_export(dir, name, &data)
        };
        match exported() {
            Ok(()) => result.exported += 1,
            Err(error) => result.failed(name.clone(), error),
        }
    }
    progress(ImportProgress { done: total, total });
    result
}

/// Export selected photos (`ids`) or the whole non-trashed library (None).
#[tauri::command]
async fn export_photos(
    dest: String,
    ids: Option<Vec<String>>,
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<ExportResult, String> {
    let (key, objects, entries, result) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        let mut result = ExportResult::default();
        let entries: Vec<(String, String)> = match &ids {
            Some(ids) => {
                let mut seen = HashSet::new();
                ids.iter()
                    .filter(|id| seen.insert((*id).clone()))
                    .filter_map(|id| match vault.photos.get(id) {
                        Some(photo) => Some((id.clone(), photo.name.clone())),
                        None => {
                            result.failed(
                                format!("Unavailable photo {id}"),
                                "Photo is no longer in the library.".into(),
                            );
                            None
                        }
                    })
                    .collect()
            }
            None => vault
                .photos
                .iter()
                .filter(|(_, photo)| photo.deleted.is_none())
                .map(|(id, photo)| (id.clone(), photo.name.clone()))
                .collect(),
        };
        (key, vault.objects_dir(), entries, result)
    };
    Ok(export_entries(
        &key,
        &objects,
        &PathBuf::from(dest),
        &entries,
        result,
        |progress| {
            let _ = app.emit("export-progress", progress);
        },
    ))
}

/// Write a consistent encrypted snapshot and publish it only after it is complete.
#[tauri::command]
async fn backup_vault(
    dest: String,
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<usize, String> {
    backup::write_backup(&PathBuf::from(dest), &state, |progress| {
        let _ = app.emit("backup-progress", progress);
    })
}

#[cfg(test)]
fn safe_backup_entry(name: &str) -> bool {
    backup::safe_entry(name)
}

/// Validate a staged backup before replacing the locked vault.
#[tauri::command]
async fn restore_backup(src: String, state: VaultState<'_>) -> Result<(), String> {
    backup::restore(&PathBuf::from(src), &state)
}

/// Backfill capture dates for photos imported before this feature existed.
#[tauri::command]
async fn scan_dates(app: tauri::AppHandle, state: VaultState<'_>) -> Result<usize, String> {
    let (key, objects, ids) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        let ids: Vec<String> = vault
            .photos
            .iter()
            .filter(|(_, p)| p.taken.is_none() && !is_video_name(&p.name))
            .map(|(id, _)| id.clone())
            .collect();
        (key, vault.objects_dir(), ids)
    };
    let total = ids.len();
    let mut updates: Vec<(String, f64)> = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        if i % 20 == 0 {
            let _ = app.emit("scan-progress", ImportProgress { done: i, total });
        }
        let Ok(blob) = fs::read(objects.join(id)) else {
            continue;
        };
        let Ok(data) = decrypt_owned(&key, blob) else {
            continue;
        };
        if let Some(t) = exif_taken(&data) {
            updates.push((id.clone(), t));
        }
    }
    let _ = app.emit("scan-progress", ImportProgress { done: total, total });
    let mut vault = vlock(&state);
    let key = vault.key.ok_or("locked")?;
    let n = updates.len();
    if n > 0 {
        edit_library(&mut vault, &key, |vault| {
            for (id, t) in updates {
                if let Some(p) = vault.photos.get_mut(&id) {
                    p.taken = Some(t);
                }
            }
            Ok(())
        })?;
    }
    Ok(n)
}

// ------------------------------------------------------------ media serve ---
//
// pvmedia://localhost/<id>[/thumb] serves decrypted bytes straight to the
// webview — no base64 blow-up, no plaintext on disk — with HTTP Range
// support so <video> can seek.

/// Parse a "bytes=a-b" Range header into an inclusive (start, end).
fn parse_range(header: &str, len: u64) -> Option<(u64, u64)> {
    if len == 0 {
        return None;
    }
    let spec = header.strip_prefix("bytes=")?;
    let (a, b) = spec.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.trim().parse().ok()?;
        if n == 0 {
            return None;
        }
        Some((len.saturating_sub(n), len - 1))
    } else {
        let start: u64 = a.trim().parse().ok()?;
        if start >= len {
            return None;
        }
        let end = if b.is_empty() {
            len - 1
        } else {
            b.trim().parse::<u64>().ok()?.min(len - 1)
        };
        if end < start {
            return None;
        }
        Some((start, end))
    }
}

fn mime_for(name: &str, data: &[u8]) -> String {
    match ext_of(name).as_str() {
        "mp4" | "m4v" => "video/mp4".into(),
        "mov" => "video/quicktime".into(),
        "heic" | "heif" => "image/heic".into(),
        _ => match image::guess_format(data) {
            Ok(f) => format!("image/{}", f.extensions_str().first().unwrap_or(&"jpeg")),
            Err(_) => "application/octet-stream".into(),
        },
    }
}

fn media_response(
    req: &tauri::http::Request<Vec<u8>>,
    mime: String,
    data: &[u8],
) -> tauri::http::Response<Vec<u8>> {
    let total = data.len() as u64;
    let range = req
        .headers()
        .get("range")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_range(s, total));
    let builder = tauri::http::Response::builder()
        .header("Content-Type", mime)
        .header("Accept-Ranges", "bytes")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff");
    match range {
        Some((start, end)) => builder
            .status(206)
            .header("Content-Range", format!("bytes {start}-{end}/{total}"))
            .header("Content-Length", (end - start + 1).to_string())
            .body(data[start as usize..=end as usize].to_vec())
            .unwrap(),
        None => builder
            .status(200)
            .header("Content-Length", total.to_string())
            .body(data.to_vec())
            .unwrap(),
    }
}

const THUMB_CACHE_CAP: usize = 1500; // ~60 MB at ~40 KB per thumb

fn cache_thumb(vault: &mut Vault, id: &str, data: Arc<Vec<u8>>) {
    if vault.thumb_cache.insert(id.to_string(), data).is_none() {
        vault.thumb_order.push_back(id.to_string());
    }
    while vault.thumb_cache.len() > THUMB_CACHE_CAP {
        match vault.thumb_order.pop_front() {
            Some(old) => {
                vault.thumb_cache.remove(&old);
            }
            None => break,
        }
    }
}

fn media_error(status: u16) -> tauri::http::Response<Vec<u8>> {
    tauri::http::Response::builder()
        .status(status)
        .header("X-Content-Type-Options", "nosniff")
        .body(Vec::new())
        .unwrap()
}

/// The grid reloads thumbnails on every redraw, including the automatic ones
/// after Inbox passes, so only full media (opening a photo, playing a video)
/// counts as activity. The UI reports real scrolling with touch_activity.
fn media_key(vault: &mut Vault, thumb: bool) -> Option<[u8; 32]> {
    if thumb {
        vault.background_key()
    } else {
        vault.active_key()
    }
}

fn serve_media(
    app: &tauri::AppHandle,
    req: &tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    let path = req.uri().path().to_string();
    let mut segs = path.trim_matches('/').split('/');
    let Some(id) = segs
        .next()
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()))
    else {
        return media_error(404);
    };
    let thumb = matches!(segs.next(), Some("thumb"));
    let state: State<Mutex<Vault>> = app.state();
    let (key, fpath, name, cached) = {
        let mut vault = vlock(&state);
        let Some(key) = media_key(&mut vault, thumb) else {
            return media_error(403);
        };
        let Some(info) = vault.photos.get(id) else {
            return media_error(404);
        };
        let name = info.name.clone();
        let file = if thumb {
            format!("{id}.t")
        } else {
            id.to_string()
        };
        let cached = if thumb {
            let hit = vault.thumb_cache.get(id).cloned();
            if hit.is_some() {
                // Touch for LRU: move to the back of the eviction order.
                if let Some(pos) = vault.thumb_order.iter().position(|x| x == id) {
                    let e = vault.thumb_order.remove(pos).unwrap();
                    vault.thumb_order.push_back(e);
                }
            }
            hit
        } else {
            vault
                .media_cache
                .as_ref()
                .filter(|(cid, _)| cid == id)
                .map(|(_, d)| d.clone())
        };
        (key, vault.objects_dir().join(file), name, cached)
    };
    let data: Arc<Vec<u8>> = match cached {
        Some(d) => d,
        None => {
            let Ok(blob) = fs::read(&fpath) else {
                return media_error(404);
            };
            let Ok(plain) = decrypt_owned(&key, blob) else {
                return media_error(500);
            };
            let plain = Arc::new(plain);
            let mut vault = vlock(&state);
            if vault.key.is_some() {
                if thumb {
                    cache_thumb(&mut vault, id, plain.clone());
                } else if is_video_name(&name) {
                    vault.media_cache = Some((id.to_string(), plain.clone()));
                }
            }
            plain
        }
    };
    let mime = if thumb {
        "image/jpeg".to_string()
    } else {
        mime_for(&name, &data)
    };
    media_response(req, mime, &data)
}

// ----------------------------------------------------------------- inbox ---

type FileSig = (u64, SystemTime, u64, u64, i64, i64);

fn file_signature(metadata: &fs::Metadata) -> FileSig {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.len(),
            metadata.modified().unwrap_or(UNIX_EPOCH),
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    }
    #[cfg(not(unix))]
    (
        metadata.len(),
        metadata.modified().unwrap_or(UNIX_EPOCH),
        0,
        0,
        0,
        0,
    )
}

/// Media files and zip archives anywhere under the inbox — folders dropped in
/// are walked recursively, and the result is sorted by name so files are
/// imported in the order the inbox folder shows them. Hidden entries and
/// symlinks are skipped; depth is bounded so a pathological tree can't wedge
/// the watcher.
fn scan_inbox_media(dir: &std::path::Path, depth: u32, out: &mut Vec<(PathBuf, FileSig)>) {
    if depth > 8 {
        return;
    }
    if depth == 0 {
        let Ok(meta) = fs::symlink_metadata(dir) else {
            return;
        };
        if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
            return;
        }
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if is_hidden(&path) || ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            scan_inbox_media(&path, depth + 1, out);
        } else if ft.is_file() && (is_media_path(&path) || is_zip_path(&path)) {
            if let Ok(md) = entry.metadata() {
                out.push((path, file_signature(&md)));
            }
        }
    }
    if depth == 0 {
        // Zips inside an extracted folder stay put, so nested archives can't
        // keep unpacking with a fresh size budget each.
        out.retain(|(path, _)| !is_zip_path(path) || inbox_album_name(dir, path).is_none());
        out.sort_by_cached_key(|(path, _)| path_sort_key(path));
    }
}

/// After importing a folder's media, remove the folders it leaves empty,
/// walking up to (but never into or past) the inbox root. `remove_dir` only
/// deletes empty directories, so anything still holding files survives —
/// except a Finder .DS_Store or album marker, which shouldn't keep a folder alive.
fn prune_empty_dirs(inbox: &std::path::Path, from: &std::path::Path) {
    const LEFTOVERS: [&str; 2] = [".DS_Store", INBOX_ALBUM_MARKER];
    let mut dir = from.to_path_buf();
    while dir != *inbox && dir.starts_with(inbox) {
        let only_leftovers = fs::read_dir(&dir).map_or(false, |mut entries| {
            entries.all(|e| e.map_or(false, |e| LEFTOVERS.iter().any(|n| e.file_name() == *n)))
        });
        if only_leftovers {
            for name in LEFTOVERS {
                let _ = fs::remove_file(dir.join(name));
            }
        }
        if fs::remove_dir(&dir).is_err() {
            return; // not empty (or already gone) — parents aren't empty either
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => return,
        }
    }
}

/// The album named by the nearest marker between `path` and the inbox root.
fn inbox_album_name(inbox: &std::path::Path, path: &std::path::Path) -> Option<String> {
    let read_marker = |dir: &std::path::Path| {
        let marker = dir.join(INBOX_ALBUM_MARKER);
        // Only a regular file: a planted FIFO would block the watcher.
        if !fs::symlink_metadata(&marker).is_ok_and(|m| m.is_file()) {
            return None;
        }
        let mut name = String::new();
        fs::File::open(marker)
            .and_then(|f| f.take(1024).read_to_string(&mut name))
            .ok()
            .map(|_| name)
    };
    path.ancestors()
        .skip(1)
        .take_while(|dir| *dir != inbox && dir.starts_with(inbox))
        .find_map(read_marker)
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty() && name.len() <= MAX_PHOTO_NAME_BYTES)
}

/// The id of the album called `name` (ignoring case), created if none exists,
/// and whether it was created.
fn ensure_album(state: &Mutex<Vault>, name: &str) -> Result<(String, bool), String> {
    let mut vault = vlock(state);
    let key = vault.key.ok_or("locked")?;
    let lower = name.to_lowercase();
    if let Some((id, _)) = vault
        .albums
        .iter()
        .filter(|(_, a)| a.name.to_lowercase() == lower)
        .min_by(|a, b| a.1.created.total_cmp(&b.1.created))
    {
        return Ok((id.clone(), false));
    }
    let id = random_id();
    vault.albums.insert(
        id.clone(),
        Album {
            name: name.to_string(),
            created: now_secs(),
        },
    );
    if let Err(e) = persist_index(&vault, &key) {
        vault.albums.remove(&id);
        return Err(e);
    }
    Ok((id, true))
}

/// Discard staging folders left by an extraction that was interrupted.
fn remove_unzip_staging(inbox: &std::path::Path) {
    let Ok(entries) = fs::read_dir(inbox) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(UNZIP_STAGING_PREFIX)
        {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn zip_failure(error: zip::result::ZipError) -> ImportFailure {
    match error {
        zip::result::ZipError::Io(e) => unzip_io_failure(e),
        other => ImportFailure::permanent(format!("Cannot extract archive: {other}")),
    }
}

/// Errors the archive itself causes recur on every attempt, so they're
/// permanent until the zip changes or Process Inbox runs. A full or read-only
/// disk can be fixed by the user, so it retries after a long wait instead of
/// refilling the disk every minute.
fn unzip_io_failure(e: std::io::Error) -> ImportFailure {
    use std::io::ErrorKind::*;
    let reason = format!("Cannot extract archive: {e}");
    match e.kind() {
        StorageFull | QuotaExceeded | ReadOnlyFilesystem => ImportFailure {
            reason: format!("{reason}. It will be retried later."),
            retryable: true,
            slow_retry: true,
        },
        FileTooLarge | InvalidFilename | AlreadyExists | NotADirectory | IsADirectory
        | InvalidData => ImportFailure::permanent(reason),
        _ => ImportFailure::temporary(reason),
    }
}

/// Give an extracted file the entry's UTC timestamp, which videos use as
/// their date. The basic zip time has no time zone, so it is ignored, and a
/// future time is capped so the inbox age check never holds the file back.
fn set_entry_time(file: &fs::File, entry: &zip::read::ZipFile<'_>) {
    let Some(secs) = entry.extra_data_fields().find_map(|field| match field {
        zip::ExtraField::ExtendedTimestamp(t) => t.mod_time(),
        _ => None,
    }) else {
        return;
    };
    let time = (UNIX_EPOCH + Duration::from_secs(secs.into())).min(SystemTime::now());
    let times = fs::FileTimes::new().set_modified(time);
    #[cfg(target_os = "macos")]
    let times = {
        use std::os::macos::fs::FileTimesExt;
        times.set_created(time)
    };
    let _ = file.set_times(times);
}

/// Write the archive's files under `dest`. Returns the media among them and
/// how many symlink entries were left out. `__MACOSX` resource forks,
/// `.DS_Store`, and album markers are skipped, so an archive can't choose
/// its own album.
fn extract_archive(
    archive: &mut zip::ZipArchive<fs::File>,
    dest: &std::path::Path,
) -> Result<(Vec<PathBuf>, usize), ImportFailure> {
    if archive.len() > MAX_UNZIP_ENTRIES {
        return Err(ImportFailure::permanent(format!(
            "Archive has more than {MAX_UNZIP_ENTRIES} entries."
        )));
    }
    let mut total = 0u64;
    for i in 0..archive.len() {
        total = total.saturating_add(archive.by_index_raw(i).map_err(zip_failure)?.size());
    }
    if total > MAX_UNZIP_BYTES {
        return Err(ImportFailure::permanent(format!(
            "Archive expands to more than {} GB.",
            MAX_UNZIP_BYTES >> 30
        )));
    }
    let mut media = Vec::new();
    let mut links = 0;
    let mut dirs = HashSet::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(zip_failure)?;
        let entry_name = entry.name().to_string();
        let unsafe_path =
            || ImportFailure::permanent(format!("Archive entry has an unsafe path: {entry_name}"));
        let enclosed = entry.enclosed_name().ok_or_else(unsafe_path)?;
        let mut relative = PathBuf::new();
        for part in enclosed.components() {
            match part {
                std::path::Component::Normal(part) => relative.push(part),
                std::path::Component::ParentDir => {
                    relative.pop();
                }
                std::path::Component::CurDir => {}
                _ => return Err(unsafe_path()),
            }
        }
        let Some(file_name) = relative
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
        else {
            continue;
        };
        if entry.is_dir()
            || relative.components().any(|c| c.as_os_str() == "__MACOSX")
            || file_name == ".DS_Store"
            || file_name == INBOX_ALBUM_MARKER
        {
            continue;
        }
        if entry.is_symlink() {
            links += 1;
            continue;
        }
        // The extracted folder sits one level below the inbox, and the scanner
        // stops eight levels down.
        if relative.components().count() > 8 {
            return Err(ImportFailure::permanent(format!(
                "Archive entry is nested too deeply to import: {entry_name}"
            )));
        }
        let size = entry.size();
        let parent = dest.join(&relative);
        let parent = parent.parent().unwrap_or(dest);
        fs::create_dir_all(parent).map_err(unzip_io_failure)?;
        dirs.extend(
            parent
                .ancestors()
                .take_while(|d| d.starts_with(dest))
                .map(PathBuf::from),
        );
        let path = unique_dest(parent, &file_name);
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(unzip_io_failure)?;
        // One extra byte detects an entry that inflates past its declared size.
        let copied =
            std::io::copy(&mut (&mut entry).take(size + 1), &mut out).map_err(unzip_io_failure)?;
        if copied != size {
            return Err(ImportFailure::permanent(format!(
                "Archive entry {entry_name} does not match its recorded size."
            )));
        }
        set_entry_time(&out, &entry);
        out.sync_all().map_err(unzip_io_failure)?;
        // Hidden files are kept but not imported, as the scanner treats them.
        let hidden = relative
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'));
        if is_media_path(&path) && !hidden {
            media.push(path);
        }
    }
    for dir in &dirs {
        sync_dir(dir).map_err(ImportFailure::temporary)?;
    }
    Ok((media, links))
}

/// Hash a file in chunks. Archives are too big to read into memory.
/// Extract an inbox zip into a folder named after it, marked so its media is
/// filed into an album of the same name. Entries are written to a hidden
/// staging folder first, so the scanner never sees a partly written file.
/// Returns the folder, its media, the skipped symlink count, and the
/// identity and content hash of the zip that was read.
fn extract_inbox_archive(
    inbox: &std::path::Path,
    zip_path: &std::path::Path,
) -> Result<(PathBuf, Vec<PathBuf>, usize, SourceProof), ImportFailure> {
    let album = zip_path
        .file_stem()
        .map(|s| s.to_string_lossy().trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ImportFailure::permanent("Archive name can't be used as an album name."))?;
    let before = fs::symlink_metadata(zip_path).map_err(ImportFailure::temporary)?;
    let mut file = fs::File::open(zip_path).map_err(ImportFailure::temporary)?;
    let metadata = file.metadata().map_err(ImportFailure::temporary)?;
    if before.file_type().is_symlink() || !same_source(&before, &metadata) {
        return Err(ImportFailure::temporary(
            "Archive changed before it could be read.",
        ));
    }
    // Cleanup deletes the zip only if its contents still match this hash.
    let hash = hash_file(&mut file).map_err(ImportFailure::temporary)?;
    std::io::Seek::rewind(&mut file).map_err(ImportFailure::temporary)?;
    let mut archive = zip::ZipArchive::new(file).map_err(zip_failure)?;
    let staging = inbox.join(format!("{UNZIP_STAGING_PREFIX}{}", random_id()));
    create_private_dir(&staging).map_err(ImportFailure::temporary)?;
    let finished = extract_archive(&mut archive, &staging).and_then(|(media, links)| {
        if media.is_empty() {
            return Err(ImportFailure::permanent(
                "Archive contains no photos or videos.",
            ));
        }
        write_file_durably(
            &staging.join(format!("{INBOX_ALBUM_MARKER}.tmp")),
            &staging.join(INBOX_ALBUM_MARKER),
            album.as_bytes(),
            &staging,
        )
        .map_err(|e| ImportFailure::temporary(String::from(e)))?;
        // A leading dot would hide the folder from the scanner.
        let folder = match album.trim_start_matches('.') {
            "" => "Archive",
            name => name,
        };
        let folder = unique_dest(inbox, folder);
        fs::rename(&staging, &folder).map_err(ImportFailure::temporary)?;
        Ok((folder, media, links))
    });
    let (folder, media, links) = finished.inspect_err(|_| {
        let _ = fs::remove_dir_all(&staging);
    })?;
    let media = media
        .into_iter()
        .filter_map(|p| p.strip_prefix(&staging).ok().map(|p| folder.join(p)))
        .collect();
    Ok((folder, media, links, SourceProof { metadata, hash }))
}

/// Extract an inbox zip, then delete it if it is unchanged. Returns the
/// extracted media; failures are reported against the zip, which is kept.
fn unzip_inbox_archive(
    inbox: &std::path::Path,
    zip_path: &std::path::Path,
    result: &mut ImportResult,
) -> Vec<PathBuf> {
    let (folder, media, links, source) = match extract_inbox_archive(inbox, zip_path) {
        Ok(extracted) => extracted,
        Err(e) => {
            result.issue(zip_path, e.reason, "import", e.retryable);
            result.issues.last_mut().unwrap().slow_retry = e.slow_retry;
            return Vec::new();
        }
    };
    let mut retained = None;
    let removed = if links > 0 {
        Err(format!(
            "{links} symbolic links in the archive were not extracted."
        ))
    } else {
        sync_dir(inbox).and_then(|_| {
            claim_and_remove(inbox, zip_path, &mut retained, |claimed| {
                let current = fs::symlink_metadata(claimed).map_err(|e| e.to_string())?;
                if !same_source(&source.metadata, &current)
                    || fs::File::open(claimed)
                        .and_then(|mut file| hash_file(&mut file))
                        .map_err(|e| e.to_string())?
                        != source.hash
                {
                    return Err("Archive changed while it was being extracted; the changed file was preserved.".into());
                }
                Ok(())
            })
        })
    };
    if let Err(e) = removed {
        // Not retryable: extracting again would only produce a second copy.
        result.issue(
            zip_path,
            format!(
                "{e} The archive was kept. Its contents are in {}.",
                folder.display()
            ),
            "cleanup",
            false,
        );
        result.issues.last_mut().unwrap().retry_path = retained;
    }
    media
}

/// File duplicates found in album folders into their album, then remove their
/// sources. Sources stay in the inbox if the album assignment can't be saved.
/// Returns false if any assignment wasn't saved.
fn file_inbox_duplicates(
    state: &Mutex<Vault>,
    filing: &mut Vec<(PathBuf, String, SourceProof, String)>,
    inbox: &std::path::Path,
    result: &mut ImportResult,
    notify: &mut impl FnMut(InboxEvent),
) -> bool {
    let mut by_album: HashMap<&str, Vec<String>> = HashMap::new();
    for (_, id, _, album) in filing.iter() {
        by_album.entry(album).or_default().push(id.clone());
    }
    let albums = by_album.len();
    let failed: HashMap<String, String> = by_album
        .into_iter()
        .filter_map(|(album, ids)| {
            file_existing_into_album(state, &ids, album)
                .err()
                .map(|e| (album.to_string(), e))
        })
        .collect();
    if failed.len() < albums {
        notify(InboxEvent::LibraryChanged);
    }
    for (path, id, proof, album) in filing.drain(..) {
        match failed.get(&album) {
            Some(e) => result.issue(
                &path,
                format!("Could not add existing photo to album: {e}"),
                "import",
                true,
            ),
            None => {
                result.skipped += 1;
                cleanup_inbox_source(state, inbox, &path, &id, &proof, result);
            }
        }
    }
    failed.is_empty()
}

/// What `run_inbox_import` reports while it works.
enum InboxEvent {
    Progress(ImportProgress),
    /// An index save added photos, an album, or album filings.
    LibraryChanged,
}

/// Import inbox files and remove only plaintext originals whose encrypted
/// object and index entry are safely persisted. Failed/undecodable files stay
/// in the inbox so the user can inspect or replace them. Loose files go
/// first, then each zip is extracted and imported in turn, so one archive's
/// photos are saved before the next is unpacked. Media under an album marker
/// is filed into that album.
fn run_inbox_import(
    files: Vec<PathBuf>,
    key: [u8; 32],
    objects: PathBuf,
    mut hashes: HashMap<String, String>,
    skip_dups: bool,
    inbox: &std::path::Path,
    mut notify: impl FnMut(InboxEvent),
    state: &Mutex<Vault>,
) -> ImportResult {
    let mut result = ImportResult::default();
    remove_unzip_staging(inbox);
    let (zips, mut files): (Vec<_>, Vec<_>) = files.into_iter().partition(|p| is_zip_path(p));
    let mut zips = zips.iter();
    // Files attempted in earlier groups, and all files found so far.
    let mut done = 0;
    let mut total = files.len();
    // Progress is sent at most twice a second so a large pass doesn't flood the UI.
    let mut last_progress: Option<Instant> = None;
    let mut batch = Vec::new();
    let mut pending = Vec::new();
    // Duplicates from album folders, waiting to be filed into their album.
    let mut filing = Vec::new();
    let mut albums: HashMap<String, Result<String, String>> = HashMap::new();
    loop {
        let mut saved = true;
        for (i, path) in files.iter().enumerate() {
            if last_progress.is_none_or(|at| at.elapsed() >= Duration::from_millis(500)) {
                notify(InboxEvent::Progress(ImportProgress {
                    done: done + i,
                    total,
                }));
                last_progress = Some(Instant::now());
            }
            let album = match inbox_album_name(inbox, path).map(|name| {
                albums.entry(name).or_insert_with_key(|name| {
                    ensure_album(state, name).map(|(id, created)| {
                        if created {
                            notify(InboxEvent::LibraryChanged);
                        }
                        id
                    })
                })
            }) {
                None => None,
                Some(Ok(id)) => Some(id.clone()),
                Some(Err(e)) => {
                    result.issue(path, format!("Could not create album: {e}"), "import", true);
                    saved = false;
                    continue;
                }
            };
            let mut outcome = import_one(&key, &objects, path, &mut hashes, skip_dups);
            if let ImportOutcome::Skipped(existing, _) = &outcome {
                if batch.iter().any(|(id, _)| id == existing)
                    && !commit_inbox_batch(
                        state,
                        &mut batch,
                        &mut pending,
                        inbox,
                        &mut result,
                        &mut notify,
                    )
                {
                    for path in &files[i..] {
                        result.issue(
                            path,
                            "Not imported because the index could not be saved.".into(),
                            "import",
                            true,
                        );
                    }
                    saved = false;
                    break;
                }
                if !skipped_target_is_live(state, existing) {
                    outcome = import_one(&key, &objects, path, &mut hashes, false);
                }
            }
            match outcome {
                ImportOutcome::Added(id, mut info, proof) => {
                    info.albums.extend(album);
                    pending.push((path.clone(), id.clone(), proof));
                    batch.push((id, info));
                    if batch.len() >= 20
                        && !commit_inbox_batch(
                            state,
                            &mut batch,
                            &mut pending,
                            inbox,
                            &mut result,
                            &mut notify,
                        )
                    {
                        for path in &files[i + 1..] {
                            result.issue(
                                path,
                                "Not attempted because the index could not be saved.".into(),
                                "import",
                                true,
                            );
                        }
                        saved = false;
                        break;
                    }
                }
                ImportOutcome::Skipped(id, proof) => match album {
                    Some(album) => {
                        filing.push((path.clone(), id, proof, album));
                        if filing.len() >= 20
                            && !file_inbox_duplicates(
                                state,
                                &mut filing,
                                inbox,
                                &mut result,
                                &mut notify,
                            )
                        {
                            saved = false;
                        }
                    }
                    None => {
                        result.skipped += 1;
                        cleanup_inbox_source(state, inbox, path, &id, &proof, &mut result);
                    }
                },
                ImportOutcome::Failed(e) => result.issue(path, e.reason, "import", e.retryable),
            }
        }
        done += files.len();
        // Save this group before unpacking the next zip, which can take minutes.
        // Always try: a failed album save still leaves other photos to commit.
        let committed = commit_inbox_batch(
            state,
            &mut batch,
            &mut pending,
            inbox,
            &mut result,
            &mut notify,
        );
        let filed = file_inbox_duplicates(state, &mut filing, inbox, &mut result, &mut notify);
        if !(saved && committed && filed) {
            for zip in zips.by_ref() {
                result.issue(
                    zip,
                    "Not attempted because the index could not be saved.".into(),
                    "import",
                    true,
                );
            }
        }
        let Some(zip) = zips.next() else { break };
        // A zero total tells the UI an archive is being unpacked.
        notify(InboxEvent::Progress(ImportProgress { done: 0, total: 0 }));
        last_progress = None;
        files = unzip_inbox_archive(inbox, zip, &mut result);
        sort_paths_by_name(&mut files);
        total += files.len();
    }
    notify(InboxEvent::Progress(ImportProgress { done: total, total }));
    result
}

fn cleanup_inbox_source(
    state: &Mutex<Vault>,
    inbox: &std::path::Path,
    path: &std::path::Path,
    id: &str,
    proof: &SourceProof,
    result: &mut ImportResult,
) {
    // Keep delete/trash from removing the duplicate target until source cleanup finishes.
    let vault = vlock(state);
    let mut retained = None;
    let mut saved = || -> Result<(), String> {
        let key = vault.key.ok_or("Vault locked before original cleanup.")?;
        let info = vault
            .photos
            .get(id)
            .filter(|p| p.deleted.is_none())
            .ok_or("Saved photo was removed before original cleanup.")?;
        if info.hash.as_deref() != Some(proof.hash.to_hex().as_str()) {
            return Err("Saved photo no longer matches the original.".into());
        }
        // Old objects may predate durable writes. Verify and sync duplicates before discarding plaintext.
        let object = vault.objects_dir().join(id);
        let encrypted = fs::read(&object).map_err(|e| e.to_string())?;
        if blake3::hash(&decrypt_owned(&key, encrypted)?) != proof.hash {
            return Err("Saved encrypted original is damaged.".into());
        }
        fs::File::open(&object)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        fs::File::open(vault.objects_dir().join(format!("{id}.t")))
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        sync_dir(&vault.objects_dir())?;
        delete_inbox_source(inbox, path, proof, &mut retained)
    };
    if let Err(e) = saved() {
        result.issue(path, e, "cleanup", true);
        result.issues.last_mut().unwrap().retry_path = retained;
    }
}

fn commit_inbox_batch(
    state: &Mutex<Vault>,
    batch: &mut Vec<(String, PhotoInfo)>,
    pending: &mut Vec<(PathBuf, String, SourceProof)>,
    inbox: &std::path::Path,
    result: &mut ImportResult,
    notify: &mut impl FnMut(InboxEvent),
) -> bool {
    if batch.is_empty() {
        return true;
    }
    if let Err(e) = flush_batch(state, batch) {
        // A lock failure leaves the batch intact; never commit it after reporting it failed.
        batch.clear();
        for (path, _, _) in pending.drain(..) {
            result.issue(
                &path,
                format!("Could not save library index: {e}"),
                "import",
                true,
            );
        }
        return false;
    }
    notify(InboxEvent::LibraryChanged);
    result.imported += pending.len();
    for (path, id, proof) in pending.drain(..) {
        cleanup_inbox_source(state, inbox, &path, &id, &proof, result);
    }
    true
}

/// Manually process media that accumulated in PhotoVault Inbox while the
/// vault was locked or the app was not running. Two scans avoid reading a
/// file while Finder or a browser is still copying it.
#[tauri::command]
async fn process_inbox(
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<ImportResult, String> {
    let inbox = vlock(&state).inbox.clone();
    let mut first = Vec::new();
    scan_inbox_media(&inbox, 0, &mut first);
    let first: HashMap<PathBuf, FileSig> = first.into_iter().collect();
    std::thread::sleep(Duration::from_millis(2200));
    let mut second = Vec::new();
    scan_inbox_media(&inbox, 0, &mut second);
    let files: Vec<PathBuf> = second
        .into_iter()
        .filter(|(path, sig)| {
            first.get(path) == Some(sig)
                && sig
                    .1
                    .elapsed()
                    .map_or(false, |age| age >= INBOX_MIN_FILE_AGE)
        })
        .map(|(path, _)| path)
        .collect();

    let (key, objects, hashes, skip_dups) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        (
            key,
            vault.objects_dir(),
            existing_hashes(&vault),
            vault.settings.skip_duplicates,
        )
    };
    let _import_guard = claim_import(&*state)?;
    Ok(run_inbox_import(
        files,
        key,
        objects,
        hashes,
        skip_dups,
        &inbox,
        |event| {
            if let InboxEvent::Progress(progress) = event {
                let _ = app.emit("import-progress", progress);
            }
        },
        &state,
    ))
}

/// Watch the inbox folder: media saved there — loose files or entire dropped
/// folders — is encrypted into the vault and the plaintext originals removed.
/// A file is only picked up once its size/mtime is unchanged across two scans
/// (i.e. the download/copy finished), and only while the vault is unlocked.
///
/// An original is deleted only after the index entry referencing its
/// encrypted copy has been persisted — a failure (lock mid-batch, disk full)
/// leaves the plaintext in place for the next cycle, and the orphaned object
/// files are swept by cleanup_orphans. Folders emptied by an import are
/// removed too.
struct InboxRetry {
    signature: FileSig,
    attempts: u32,
    next: Option<Instant>,
}

impl InboxRetry {
    fn record(
        signature: FileSig,
        previous: Option<&Self>,
        retryable: bool,
        slow: bool,
        now: Instant,
    ) -> Self {
        let attempts = previous
            .filter(|p| p.signature == signature)
            .map_or(1, |p| p.attempts.saturating_add(1));
        let delay = match (slow, attempts) {
            (true, 1) => 10 * 60,
            (true, _) => 30 * 60,
            (false, _) => 2u64.saturating_pow(attempts.min(6)).min(60),
        };
        Self {
            signature,
            attempts,
            next: retryable.then(|| now + Duration::from_secs(delay)),
        }
    }

    fn ready(&self, signature: FileSig, now: Instant) -> bool {
        self.signature != signature || self.next.is_some_and(|next| now >= next)
    }
}

fn inbox_retry_after_failure(
    path: &std::path::Path,
    signature: FileSig,
    issue: &ImportIssue,
    previous: Option<InboxRetry>,
    now: Instant,
) -> (PathBuf, InboxRetry) {
    let retry_path = issue.retry_path.as_deref().unwrap_or(path);
    // A failure belongs to the scanned file. A replacement must not inherit its suppression.
    let retry_sig = if issue.retry_path.is_some() {
        fs::metadata(retry_path)
            .map(|metadata| file_signature(&metadata))
            .unwrap_or(signature)
    } else {
        signature
    };
    let previous = previous.map(|mut retry| {
        retry.signature = retry_sig;
        retry
    });
    let retry = InboxRetry::record(
        retry_sig,
        previous.as_ref(),
        issue.retryable,
        issue.slow_retry,
        now,
    );
    (retry_path.to_path_buf(), retry)
}

fn inbox_watcher(app: tauri::AppHandle) {
    let mut prev = HashMap::new();
    let mut retries: HashMap<PathBuf, InboxRetry> = HashMap::new();
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let state: State<Mutex<Vault>> = app.state();
        let inbox = vlock(&state).inbox.clone();
        let mut found = Vec::new();
        scan_inbox_media(&inbox, 0, &mut found);
        let cur: HashMap<_, _> = found.iter().cloned().collect();
        let ready: Vec<_> = found
            .into_iter()
            .filter(|(path, sig)| {
                prev.get(path) == Some(sig)
                    && sig.1.elapsed().is_ok_and(|age| age >= INBOX_MIN_FILE_AGE)
                    && retries
                        .get(path)
                        .is_none_or(|retry| retry.ready(*sig, Instant::now()))
            })
            .collect();
        retries.retain(|path, retry| cur.get(path) == Some(&retry.signature));
        prev = cur;
        if ready.is_empty() {
            continue;
        }
        let _import_guard = match claim_background_import(&*state) {
            Ok(guard) => guard,
            Err(_) => continue,
        };
        let (key, objects, hashes, skip_dups) = {
            let vault = vlock(&state);
            let Some(key) = vault.key else { continue };
            (
                key,
                vault.objects_dir(),
                existing_hashes(&vault),
                vault.settings.skip_duplicates,
            )
        };
        let result = run_inbox_import(
            ready.iter().map(|(path, _)| path.clone()).collect(),
            key,
            objects,
            hashes,
            skip_dups,
            &inbox,
            |event| match event {
                InboxEvent::Progress(progress) => {
                    let _ = app.emit("inbox-progress", progress);
                }
                // Lets the UI show photos and albums as soon as they're saved.
                InboxEvent::LibraryChanged => {
                    let _ = app.emit("library-changed", ());
                }
            },
            &state,
        );
        for (path, sig) in ready {
            if let Some(issue) = result
                .issues
                .iter()
                .find(|issue| issue.name == path.to_string_lossy())
            {
                let (retry_path, retry) = inbox_retry_after_failure(
                    &path,
                    sig,
                    issue,
                    retries.remove(&path),
                    Instant::now(),
                );
                retries.insert(retry_path, retry);
            } else {
                retries.remove(&path);
            }
        }
        let _ = app.emit("inbox-imported", result);
    }
}

// ------------------------------------------------------------------ main ---

fn main() {
    // Fixed worker pool for media serving: a fast scroll fires dozens of
    // thumbnail requests at once, and one OS thread per request (the old
    // scheme) let bursts starve the CPU. Six workers bound the concurrency.
    type MediaJob = (
        tauri::AppHandle,
        tauri::http::Request<Vec<u8>>,
        tauri::UriSchemeResponder,
    );
    let (media_tx, media_rx) = std::sync::mpsc::channel::<MediaJob>();
    let media_rx = Arc::new(Mutex::new(media_rx));
    for _ in 0..6 {
        let rx = media_rx.clone();
        std::thread::spawn(move || loop {
            let job = rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
            let Ok((app, request, responder)) = job else {
                return;
            };
            let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                serve_media(&app, &request)
            }))
            .unwrap_or_else(|_| media_error(500));
            responder.respond(response);
        });
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .register_asynchronous_uri_scheme_protocol("pvmedia", move |ctx, request, responder| {
            let _ = media_tx.send((ctx.app_handle().clone(), request, responder));
        })
        .setup(|app| {
            let app_dir = app.path().app_data_dir()?;
            let access = if native::another_copy_running(&app.config().identifier) {
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock,
                    "PhotoVault is already running. Quit the other copy before opening this one."))
            } else {
                instance_lock::acquire(&app_dir)
            };
            let process_lock = match access {
                Ok(file) => file,
                Err(error) => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                    let handle = app.handle().clone();
                    let message = if error.kind() == std::io::ErrorKind::WouldBlock {
                        error.to_string()
                    } else {
                        format!("PhotoVault could not secure access to the vault: {error}")
                    };
                    app.dialog().message(message).title("PhotoVault")
                        .kind(tauri_plugin_dialog::MessageDialogKind::Warning)
                        .show(move |_| handle.exit(0));
                    return Ok(());
                }
            };
            app.manage(process_lock);
            let dir = app_dir.join("vault");
            fs::create_dir_all(&dir)?;
            let inbox = app.path().home_dir()?.join("PhotoVault Inbox");
            let inbox_is_real_dir = match fs::symlink_metadata(&inbox) {
                Ok(meta) => meta.file_type().is_dir() && !meta.file_type().is_symlink(),
                Err(_) => {
                    fs::create_dir_all(&inbox)?;
                    true
                }
            };
            if !inbox_is_real_dir {
                eprintln!(
                    "PhotoVault Inbox is not a real directory; inbox watching is disabled: {}",
                    inbox.display()
                );
            }
            let settings: Settings = fs::read(dir.join("settings.json"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            let screen_protect = settings.screen_protect;
            app.manage(Mutex::new(Vault {
                dir,
                inbox,
                key: None,
                pending_recovery: None,
                session: 0,
                lock_unreported: false,
                photos: HashMap::new(),
                albums: HashMap::new(),
                recovery_required: false,
                last_activity: Instant::now(),
                importing: false,
                settings,
                meta_lock: Arc::new(Mutex::new(())),
                media_cache: None,
                thumb_cache: HashMap::new(),
                thumb_order: VecDeque::new(),
            }));
            if let Some(window) = app.get_webview_window("main") {
                if screen_protect {
                    native::set_screen_protect(&window, true);
                }
            }
            let handle = app.handle().clone();
            native::register_lock_observers(move || {
                let state: State<Mutex<Vault>> = handle.state();
                let should = {
                    let vault = vlock(&state);
                    vault.settings.lock_on_sleep && vault.key.is_some()
                };
                if should {
                    do_system_lock(&handle);
                }
            });
            if inbox_is_real_dir {
                let handle = app.handle().clone();
                std::thread::spawn(move || inbox_watcher(handle));
            }
            let handle = app.handle().clone();
            std::thread::spawn(move || lock_timer(handle));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            recovery_status,
            lock_screen_info,
            create_vault,
            unlock,
            lock,
            touch_activity,
            change_password,
            recovery_generate,
            recovery_confirm,
            recovery_disable,
            recovery_unlock,
            touchid_available,
            touchid_enable,
            touchid_disable,
            touchid_unlock,
            get_settings,
            get_build_info,
            set_settings,
            list_photos,
            list_albums,
            album_create,
            album_rename,
            album_delete,
            albums_assign,
            set_favorite,
            set_tags,
            rename_photo,
            import_photos,
            process_inbox,
            cleanup_orphans,
            trash_photos,
            restore_photos,
            purge_photos,
            empty_trash,
            clear_vault,
            export_photo,
            export_photos,
            backup_vault,
            restore_backup,
            scan_dates
        ])
        .run(tauri::generate_context!())
        .expect("error while running PhotoVault");
}

// ------------------------------------------------------------------ tests ---

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_vault(dir: PathBuf, key: Option<[u8; 32]>) -> Vault {
        Vault {
            dir,
            inbox: PathBuf::new(),
            key,
            pending_recovery: None,
            session: 0,
            lock_unreported: false,
            photos: HashMap::new(),
            albums: HashMap::new(),
            recovery_required: false,
            last_activity: Instant::now(),
            importing: false,
            settings: Settings::default(),
            meta_lock: Arc::new(Mutex::new(())),
            media_cache: None,
            thumb_cache: HashMap::new(),
            thumb_order: VecDeque::new(),
        }
    }

    fn test_photo(deleted: Option<f64>) -> PhotoInfo {
        PhotoInfo {
            name: "photo.jpg".into(),
            added: 1.0,
            size: Some(3),
            taken: None,
            hash: Some("same-hash".into()),
            favorite: false,
            deleted,
            albums: Vec::new(),
            tags: Vec::new(),
            width: None,
            height: None,
        }
    }

    #[test]
    fn crypto_roundtrip_and_tamper() {
        let key = random_key();
        let blob = encrypt(&key, b"hello world").unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), b"hello world");
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decrypt(&key, &bad).is_err());
        assert!(decrypt(&random_key(), &blob).is_err());
    }

    #[test]
    fn meta_deserializes_legacy_defaults_and_new_parameters() {
        let legacy: Meta = serde_json::from_slice(br#"{"salt":"00","verifier":"00"}"#).unwrap();
        assert_eq!(legacy.n, LEGACY_SCRYPT_LOG_N);
        assert_eq!(legacy.r, DEFAULT_SCRYPT_R);
        assert_eq!(legacy.p, DEFAULT_SCRYPT_P);

        let new: Meta = serde_json::from_slice(
            br#"{"salt":"00","verifier":"00","n":17,"r":8,"p":1,"wrapped_master":"aa"}"#,
        )
        .unwrap();
        assert_eq!((new.n, new.r, new.p), (17, 8, 1));
        assert!(new.wrapped_master.is_some());
    }

    #[test]
    fn meta_read_falls_back_to_meta_backup() {
        let dir = std::env::temp_dir().join(format!("pv-meta-{}", random_id()));
        fs::create_dir_all(&dir).unwrap();
        let master = random_key();
        let mut old = Meta {
            salt: String::new(),
            verifier: String::new(),
            n: LEGACY_SCRYPT_LOG_N,
            r: DEFAULT_SCRYPT_R,
            p: DEFAULT_SCRYPT_P,
            wrapped_master: None,
            recovery: None,
        };
        rewrap_master(&mut old, "old password", &master).unwrap();
        write_meta(&dir, &old).unwrap();
        let old_salt = old.salt.clone();
        let mut current = old;
        rewrap_master(&mut current, "new password", &master).unwrap();
        write_meta(&dir, &current).unwrap();

        // The backup is the same generation, not the previous one: the master
        // key outlives a password change, so a retired salt + wrapped_master
        // left on disk would keep the old password working forever.
        let backup: Meta =
            serde_json::from_slice(&fs::read(dir.join("meta.bak")).unwrap()).unwrap();
        assert_eq!(backup.salt, current.salt);
        for name in ["meta.json", "meta.bak"] {
            let raw = String::from_utf8(fs::read(dir.join(name)).unwrap()).unwrap();
            assert!(!raw.contains(&old_salt), "{name} still holds the retired salt");
        }

        // ...and it is still a usable fallback for a torn primary write.
        fs::write(dir.join("meta.json"), b"truncated").unwrap();
        assert_eq!(read_meta(&dir).unwrap().salt, current.salt);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_index_falls_back_to_backup_when_current_is_corrupt() {
        let dir = std::env::temp_dir().join(format!("pv-index-{}", random_id()));
        fs::create_dir_all(&dir).unwrap();
        let key = random_key();
        let vault = test_vault(dir.clone(), Some(key));
        let json = br#"{"photos":{"id":{"name":"a.jpg","added":1}},"albums":{}}"#;
        fs::write(dir.join("index.enc"), b"corrupt").unwrap();
        fs::write(dir.join("index.bak"), encrypt(&key, json).unwrap()).unwrap();
        let loaded = load_index(&vault, &key).unwrap();
        assert_eq!(loaded.photos["id"].name, "a.jpg");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_preserves_unindexed_and_expired_objects_across_saves_and_restart() {
        let dir = std::env::temp_dir().join(format!("pv-recovery-{}", random_id()));
        fs::create_dir_all(dir.join("objects")).unwrap();
        let key = random_key();
        let mut vault = test_vault(dir.clone(), None);
        vault.photos.insert("expired".into(), test_photo(Some(1.0)));
        persist_index(&vault, &key).unwrap();
        fs::copy(vault.index_path(), vault.index_bak_path()).unwrap();
        let original_backup = fs::read(vault.index_bak_path()).unwrap();
        fs::write(vault.index_path(), b"corrupt").unwrap();
        for name in ["expired", "expired.t", "newer", "newer.t"] {
            fs::write(dir.join("objects").join(name), b"intact encrypted data").unwrap();
        }
        let state = Mutex::new(vault);
        finish_unlock(&state, key).unwrap();
        {
            let mut vault = vlock(&state);
            assert!(vault.recovery_required);
            assert!(vault.photos.contains_key("expired"));
            assert!(dir.join("recovery-required").exists());
            assert_eq!(sweep_orphans(&vault), 0);
            vault.photos.get_mut("expired").unwrap().name = "Renamed.jpg".into();
            persist_index(&vault, &key).unwrap();
            assert_eq!(fs::read(vault.index_bak_path()).unwrap(), original_backup);
        }
        let restarted = Mutex::new(test_vault(dir.clone(), None));
        finish_unlock(&restarted, key).unwrap();
        {
            let vault = vlock(&restarted);
            assert!(vault.recovery_required);
            assert_eq!(vault.photos["expired"].name, "Renamed.jpg");
            assert_eq!(sweep_orphans(&vault), 0);
        }
        // The encrypted flag also survives a backup that carries only the index.
        fs::remove_file(dir.join("recovery-required")).unwrap();
        assert!(load_index(&vlock(&restarted), &key).unwrap().recovery_required);
        assert!(dir.join("recovery-required").exists());
        for name in ["expired", "expired.t", "newer", "newer.t"] {
            assert_eq!(fs::read(dir.join("objects").join(name)).unwrap(), b"intact encrypted data");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovery_marker_failure_refuses_unlock_without_deleting_objects() {
        let dir = std::env::temp_dir().join(format!("pv-recovery-failure-{}", random_id()));
        fs::create_dir_all(dir.join("objects")).unwrap();
        fs::create_dir(dir.join("recovery-required")).unwrap();
        let key = random_key();
        fs::write(dir.join("index.bak"), encrypt(&key, br#"{"photos":{},"albums":{}}"#).unwrap()).unwrap();
        fs::write(dir.join("objects/newer"), b"keep me").unwrap();
        let state = Mutex::new(test_vault(dir.clone(), None));
        assert!(finish_unlock(&state, key).is_err());
        assert!(vlock(&state).key.is_none());
        assert_eq!(fs::read(dir.join("objects/newer")).unwrap(), b"keep me");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_trash_expiry_save_still_unlocks_and_keeps_the_items() {
        let dir = std::env::temp_dir().join(format!("pv-expiry-failure-{}", random_id()));
        fs::create_dir_all(dir.join("objects")).unwrap();
        let key = random_key();
        let json = br#"{"old":{"name":"old.jpg","added":1,"deleted":1},"keep":{"name":"keep.jpg","added":2}}"#;
        fs::write(dir.join("index.enc"), encrypt(&key, json).unwrap()).unwrap();
        for name in ["old", "old.t", "keep", "keep.t"] {
            fs::write(dir.join("objects").join(name), b"fixture").unwrap();
        }
        let state = Mutex::new(test_vault(dir.clone(), None));
        let index_tmp = vlock(&state).index_path().with_extension("tmp");
        fs::create_dir(&index_tmp).unwrap();
        finish_unlock(&state, key).unwrap();
        let vault = vlock(&state);
        assert_eq!(vault.key, Some(key));
        assert!(vault.photos.contains_key("old"));
        assert!(dir.join("objects/old").exists());
        assert!(dir.join("objects/old.t").exists());
        drop(vault);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn healthy_legacy_index_still_expires_trash_and_cleans_orphans() {
        let dir = std::env::temp_dir().join(format!("pv-healthy-{}", random_id()));
        fs::create_dir_all(dir.join("objects")).unwrap();
        let key = random_key();
        let json = br#"{"old":{"name":"old.jpg","added":1,"deleted":1},"keep":{"name":"keep.jpg","added":2}}"#;
        fs::write(dir.join("index.enc"), encrypt(&key, json).unwrap()).unwrap();
        for name in ["old", "old.t", "keep", "keep.t", "orphan"] {
            fs::write(dir.join("objects").join(name), b"fixture").unwrap();
        }
        let state = Mutex::new(test_vault(dir.clone(), None));
        finish_unlock(&state, key).unwrap();
        let vault = vlock(&state);
        assert!(!vault.recovery_required);
        assert!(!vault.photos.contains_key("old"));
        assert!(!dir.join("objects/old").exists());
        assert!(!dir.join("objects/old.t").exists());
        assert_eq!(sweep_orphans(&vault), 1);
        assert!(dir.join("objects/keep").exists());
        assert!(dir.join("objects/keep.t").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn flush_batch_rolls_back_memory_when_persist_fails() {
        let dir = std::env::temp_dir().join(format!("pv-no-dir-{}", random_id()));
        let key = random_key();
        let state = Mutex::new(test_vault(dir, Some(key)));
        let id = "new-photo".to_string();
        let mut batch = vec![(id.clone(), test_photo(None))];
        assert!(flush_batch(&state, &mut batch).is_err());
        assert!(batch.is_empty());
        assert!(!vlock(&state).photos.contains_key(&id));
    }

    #[test]
    fn inbox_plaintext_survives_when_index_persist_fails() {
        let inbox = std::env::temp_dir().join(format!("pv-inbox-fail-{}", random_id()));
        fs::create_dir_all(&inbox).unwrap();
        let plaintext = inbox.join("photo.jpg");
        fs::write(&plaintext, b"plaintext").unwrap();
        let state_dir = std::env::temp_dir().join(format!("pv-no-index-{}", random_id()));
        let state = Mutex::new(test_vault(state_dir, Some(random_key())));
        let mut batch = vec![("id".into(), test_photo(None))];
        let (_, proof) = read_source(&plaintext).unwrap();
        let mut pending = vec![(plaintext.clone(), "id".into(), proof)];
        let mut result = ImportResult::default();
        let mut changed = false;
        let mut notify = |_| changed = true;
        assert!(!commit_inbox_batch(
            &state,
            &mut batch,
            &mut pending,
            &inbox,
            &mut result,
            &mut notify
        ));
        assert!(!changed);
        assert_eq!(result.imported, 0);
        assert_eq!(result.failed, 1);
        assert!(plaintext.exists());
        let _ = fs::remove_dir_all(&inbox);
    }

    #[test]
    fn existing_hashes_excludes_trashed_photos() {
        let mut vault = test_vault(PathBuf::new(), Some(random_key()));
        vault.photos.insert("live".into(), test_photo(None));
        vault.photos.insert("trash".into(), test_photo(Some(10.0)));
        let hashes = existing_hashes(&vault);
        assert_eq!(hashes.get("same-hash"), Some(&"live".to_string()));
        vault.photos.remove("live");
        assert!(!existing_hashes(&vault).contains_key("same-hash"));
    }

    #[test]
    fn album_targeted_duplicate_filing_persists_album_assignment() {
        let dir = std::env::temp_dir().join(format!("pv-album-{}", random_id()));
        fs::create_dir_all(&dir).unwrap();
        let key = random_key();
        let mut vault = test_vault(dir.clone(), Some(key));
        vault.albums.insert(
            "album".into(),
            Album {
                name: "Trip".into(),
                created: 1.0,
            },
        );
        vault.photos.insert("photo".into(), test_photo(None));
        let state = Mutex::new(vault);
        file_existing_into_album(&state, &["photo".into()], "album").unwrap();
        assert_eq!(vlock(&state).photos["photo"].albums, vec!["album"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn envelope_wrap_unwrap_and_password_change() {
        let master = random_key();
        let mut meta = Meta {
            salt: String::new(),
            verifier: String::new(),
            n: LEGACY_SCRYPT_LOG_N,
            r: DEFAULT_SCRYPT_R,
            p: DEFAULT_SCRYPT_P,
            wrapped_master: None,
            recovery: None,
        };
        rewrap_master(&mut meta, "first password", &master).unwrap();
        assert_eq!(
            master_from_password("first password", &meta).unwrap(),
            master
        );
        assert!(master_from_password("wrong password", &meta).is_err());
        // Password change re-wraps the same master key.
        rewrap_master(&mut meta, "second password", &master).unwrap();
        assert!(master_from_password("first password", &meta).is_err());
        assert_eq!(
            master_from_password("second password", &meta).unwrap(),
            master
        );
    }

    #[test]
    fn v1_meta_still_unlocks() {
        // v1 layout: master derived directly from password, no wrapped_master.
        let salt = [7u8; 16];
        let master = derive_key("legacy password", &salt).unwrap();
        let meta = Meta {
            salt: hex::encode(salt),
            verifier: hex::encode(encrypt(&master, VERIFIER_PLAINTEXT).unwrap()),
            n: LEGACY_SCRYPT_LOG_N,
            r: DEFAULT_SCRYPT_R,
            p: DEFAULT_SCRYPT_P,
            wrapped_master: None,
            recovery: None,
        };
        assert_eq!(
            master_from_password("legacy password", &meta).unwrap(),
            master
        );
        assert!(master_from_password("not it", &meta).is_err());
    }

    #[test]
    fn recovery_key_roundtrip() {
        let master = random_key();
        let rk = random_key();
        let wrapped = encrypt(&rk, &master).unwrap();
        let formatted = format_recovery_key(&rk);
        assert_eq!(formatted.len(), 64 + 15); // 16 groups of 4 + 15 dashes
        let parsed = parse_recovery_key(&formatted).unwrap();
        assert_eq!(parsed, rk);
        // Sloppy input still parses.
        let sloppy = formatted.to_lowercase().replace('-', " ");
        assert_eq!(parse_recovery_key(&sloppy).unwrap(), rk);
        let unwrapped = decrypt(&parsed, &wrapped).unwrap();
        assert_eq!(unwrapped, master);
    }

    #[test]
    fn index_parses_legacy_and_v2() {
        let legacy = br#"{"aabb01":{"name":"a.jpg","added":1.5,"size":10}}"#;
        let data = parse_index(legacy).unwrap();
        assert_eq!(data.photos.len(), 1);
        assert!(data.albums.is_empty());
        assert_eq!(data.photos["aabb01"].name, "a.jpg");
        assert!(!data.photos["aabb01"].favorite);
        assert!(data.photos["aabb01"].deleted.is_none());

        let v2 = br#"{"photos":{"cc":{"name":"b.png","added":2.0,"favorite":true}},"albums":{"a1":{"name":"Trip","created":3.0}}}"#;
        let data = parse_index(v2).unwrap();
        assert!(data.photos["cc"].favorite);
        assert_eq!(data.albums["a1"].name, "Trip");

        let empty_legacy = br#"{}"#;
        let data = parse_index(empty_legacy).unwrap();
        assert!(data.photos.is_empty());
    }

    #[test]
    fn range_header_parsing() {
        assert_eq!(parse_range("bytes=0-1", 10), Some((0, 1)));
        assert_eq!(parse_range("bytes=0-", 10), Some((0, 9)));
        assert_eq!(parse_range("bytes=5-100", 10), Some((5, 9)));
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(parse_range("bytes=10-", 10), None);
        assert_eq!(parse_range("bytes=4-2", 10), None);
        assert_eq!(parse_range("nonsense", 10), None);
        assert_eq!(parse_range("bytes=0-1", 0), None);
    }

    #[test]
    fn exif_epoch_conversion() {
        assert_eq!(civil_to_epoch(1970, 1, 1, 0, 0, 0), 0.0);
        assert_eq!(civil_to_epoch(2020, 3, 1, 0, 0, 0), 1583020800.0);
        assert_eq!(civil_to_epoch(2026, 7, 3, 12, 30, 15), 1783081815.0);
    }

    #[test]
    fn unique_dest_appends_counter() {
        let dir = std::env::temp_dir().join(format!("pv-test-{}", random_id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_dest(&dir, "a.jpg"), dir.join("a.jpg"));
        fs::write(dir.join("a.jpg"), b"x").unwrap();
        assert_eq!(unique_dest(&dir, "a.jpg"), dir.join("a (1).jpg"));
        fs::write(dir.join("a (1).jpg"), b"x").unwrap();
        assert_eq!(unique_dest(&dir, "a.jpg"), dir.join("a (2).jpg"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_key_orders_leading_zero_ties_deterministically() {
        assert!(name_key("0") < name_key("00"));
        assert!(name_key("01") < name_key("1"));
        assert_ne!(name_key("0"), name_key("00"));
        assert_ne!(name_key("01"), name_key("1"));
    }

    #[test]
    fn export_destination_cannot_escape_directory() {
        let dir = PathBuf::from("/tmp/export");
        assert_eq!(
            unique_dest(&dir, "../../outside.jpg"),
            dir.join("outside.jpg")
        );
        assert_eq!(unique_dest(&dir, "/absolute.jpg"), dir.join("absolute.jpg"));
        assert_eq!(sanitize_photo_name("safe.jpg").unwrap(), "safe.jpg");
        assert!(sanitize_photo_name("../outside.jpg").is_err());
        assert!(sanitize_photo_name("-unsafe.jpg").is_err());
        assert!(sanitize_photo_name(".hidden.jpg").is_err());
    }

    #[test]
    fn import_guard_clears_flag_during_unwind() {
        let state = Mutex::new(test_vault(PathBuf::new(), Some(random_key())));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = claim_import(&state).unwrap();
            panic!("simulated import panic");
        }));
        assert!(result.is_err());
        assert!(!vlock(&state).importing);
    }

    #[test]
    fn collected_files_follow_name_order_not_creation_order() {
        let root = std::env::temp_dir().join(format!("pv-order-{}", random_id()));
        fs::create_dir_all(root.join("Trip")).unwrap();
        // Written newest-name-first so creation order contradicts name order.
        for name in ["IMG_10.jpg", "IMG_9.jpg", "IMG_2.jpg"] {
            fs::write(root.join(name), b"x").unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        fs::write(root.join("Trip/b.jpg"), b"x").unwrap();
        fs::write(root.join("Trip/a.jpg"), b"x").unwrap();

        let found = collect_files(&[root.to_string_lossy().into_owned()], &mut ImportResult::default());
        assert_eq!(
            found,
            [
                root.join("IMG_2.jpg"),
                root.join("IMG_9.jpg"),
                root.join("IMG_10.jpg"),
                // A folder's contents stay together, in name order.
                root.join("Trip/a.jpg"),
                root.join("Trip/b.jpg"),
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn name_order_is_natural_and_deterministic() {
        let mut paths: Vec<PathBuf> = ["b/1.jpg", "a/10.jpg", "a/9.jpg", "A/2.jpg", "a/007.jpg"]
            .iter()
            .map(PathBuf::from)
            .collect();
        sort_paths_by_name(&mut paths);
        assert_eq!(
            paths,
            [
                // "A" and "a" fold to the same key, so their files interleave
                // by the next component; digits compare as numbers throughout.
                PathBuf::from("A/2.jpg"),
                PathBuf::from("a/007.jpg"),
                PathBuf::from("a/9.jpg"),
                PathBuf::from("a/10.jpg"),
                PathBuf::from("b/1.jpg"),
            ]
        );
    }

    #[test]
    fn backup_entry_validation() {
        for ok in [
            "meta.json",
            "settings.json",
            "index.enc",
            "index.bak",
            "objects/",
            "objects/aabb01",
            "objects/aabb01.t",
        ] {
            assert!(safe_backup_entry(ok), "{ok} should be accepted");
        }
        for bad in [
            "../evil",
            "/etc/passwd",
            "objects/../meta.json",
            "objects/a/b",
            "meta.json.bak",
            "objects",
            "a\\b",
            "",
        ] {
            assert!(!safe_backup_entry(bad), "{bad} should be rejected");
        }
    }

    #[test]
    fn tag_normalization() {
        assert_eq!(
            normalize_tags(vec![
                "  Beach ".into(),
                "beach".into(),
                "".into(),
                "  ".into(),
                "Sunset".into(),
                "BEACH".into(),
                "sunset ".into(),
                "Dog".into(),
            ]),
            vec!["Beach".to_string(), "Sunset".to_string(), "Dog".to_string()]
        );
        assert!(normalize_tags(vec![]).is_empty());
    }

    #[test]
    fn thumb_cache_evicts_lru() {
        let mut vault = Vault {
            dir: PathBuf::new(),
            inbox: PathBuf::new(),
            key: None,
            pending_recovery: None,
            session: 0,
            lock_unreported: false,
            photos: HashMap::new(),
            albums: HashMap::new(),
            recovery_required: false,
            last_activity: Instant::now(),
            importing: false,
            settings: Settings::default(),
            meta_lock: Arc::new(Mutex::new(())),
            media_cache: None,
            thumb_cache: HashMap::new(),
            thumb_order: VecDeque::new(),
        };
        for i in 0..THUMB_CACHE_CAP + 10 {
            cache_thumb(&mut vault, &format!("id{i}"), Arc::new(vec![0u8]));
        }
        assert_eq!(vault.thumb_cache.len(), THUMB_CACHE_CAP);
        assert!(!vault.thumb_cache.contains_key("id0"));
        assert!(vault
            .thumb_cache
            .contains_key(&format!("id{}", THUMB_CACHE_CAP + 9)));
        // Re-inserting an existing id must not duplicate its order entry.
        cache_thumb(
            &mut vault,
            &format!("id{}", THUMB_CACHE_CAP + 9),
            Arc::new(vec![1u8]),
        );
        assert_eq!(vault.thumb_order.len(), vault.thumb_cache.len());
    }

    #[test]
    fn inbox_scan_recurses_and_skips_hidden() {
        let root = std::env::temp_dir().join(format!("pv-inbox-{}", random_id()));
        fs::create_dir_all(root.join("Trip/day2")).unwrap();
        fs::create_dir_all(root.join(".hiddendir")).unwrap();
        fs::write(root.join("top.jpg"), b"x").unwrap();
        fs::write(root.join("notes.txt"), b"x").unwrap();
        fs::write(root.join("Trip/a.png"), b"x").unwrap();
        fs::write(root.join("Trip/day2/b.mov"), b"x").unwrap();
        fs::write(root.join("Trip/.DS_Store"), b"x").unwrap();
        fs::write(root.join(".hiddendir/c.jpg"), b"x").unwrap();
        let mut found = Vec::new();
        scan_inbox_media(&root, 0, &mut found);
        let mut names: Vec<String> = found
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["a.png", "b.mov", "top.jpg"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_removes_emptied_dirs_but_not_inbox_or_occupied() {
        let root = std::env::temp_dir().join(format!("pv-prune-{}", random_id()));
        fs::create_dir_all(root.join("Trip/day2")).unwrap();
        fs::write(root.join("Trip/.DS_Store"), b"x").unwrap();
        // Empty leaf + .DS_Store-only parent: both go; the inbox root stays.
        prune_empty_dirs(&root, &root.join("Trip/day2"));
        assert!(!root.join("Trip").exists());
        assert!(root.exists());
        // A dir still holding a real file survives, .DS_Store or not.
        fs::create_dir_all(root.join("Keep")).unwrap();
        fs::write(root.join("Keep/left.jpg"), b"x").unwrap();
        fs::write(root.join("Keep/.DS_Store"), b"x").unwrap();
        prune_empty_dirs(&root, &root.join("Keep"));
        assert!(root.join("Keep/left.jpg").exists());
        assert!(root.join("Keep/.DS_Store").exists());
        // An extracted zip folder holding only its album marker goes too.
        fs::create_dir_all(root.join("Zip")).unwrap();
        fs::write(root.join("Zip").join(INBOX_ALBUM_MARKER), b"Zip").unwrap();
        prune_empty_dirs(&root, &root.join("Zip"));
        assert!(!root.join("Zip").exists());
        // Never climbs above the inbox root.
        prune_empty_dirs(&root.join("nope"), &root);
        assert!(root.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn media_kind_detection() {
        assert!(is_video_name("clip.MOV"));
        assert!(is_video_name("movie.mp4"));
        assert!(!is_video_name("photo.heic"));
        assert!(is_media_path(std::path::Path::new("/x/IMG_1.HEIC")));
        assert!(is_media_path(std::path::Path::new("/x/v.m4v")));
        assert!(!is_media_path(std::path::Path::new("/x/notes.txt")));
    }


    struct ImportFixture {
        root: PathBuf,
        inbox: PathBuf,
        key: [u8; 32],
        state: Mutex<Vault>,
    }

    impl ImportFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("pv-ingestion-{}", random_id()));
            let inbox = root.join("inbox");
            let dir = root.join("vault");
            fs::create_dir_all(&inbox).unwrap();
            fs::create_dir_all(dir.join("objects")).unwrap();
            let key = random_key();
            Self {
                root,
                inbox,
                key,
                state: Mutex::new(test_vault(dir, Some(key))),
            }
        }

        fn photo(&self, name: &str, color: u8) -> PathBuf {
            let path = self.inbox.join(name);
            image::RgbImage::from_pixel(2, 2, image::Rgb([color, 1, 2]))
                .save(&path)
                .unwrap();
            path
        }

        fn run(&self, files: Vec<PathBuf>, notify: impl FnMut(InboxEvent)) -> ImportResult {
            let vault = vlock(&self.state);
            let objects = vault.objects_dir();
            let hashes = existing_hashes(&vault);
            drop(vault);
            run_inbox_import(
                files,
                self.key,
                objects,
                hashes,
                true,
                &self.inbox,
                notify,
                &self.state,
            )
        }
    }

    impl Drop for ImportFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn png_bytes(color: u8) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        image::RgbImage::from_pixel(2, 2, image::Rgb([color, 1, 2]))
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    fn write_zip(path: &std::path::Path, entries: &[(&str, &[u8])]) {
        let mut zip = zip::ZipWriter::new(fs::File::create(path).unwrap());
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }

    fn inbox_names(inbox: &std::path::Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(inbox)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn inbox_zip_is_extracted_into_an_album_named_after_it() {
        let fixture = ImportFixture::new();
        let owned = fixture.inbox.join("owned.png");
        fs::write(&owned, png_bytes(9)).unwrap();
        assert_eq!(fixture.run(vec![owned], |_| {}).imported, 1);

        let zip_path = fixture.inbox.join("Summer Trip.zip");
        let inner = fixture.root.join("inner.zip");
        write_zip(&inner, &[("deep.png", &png_bytes(5))]);
        write_zip(
            &zip_path,
            &[
                ("a.png", &png_bytes(1)),
                ("./day2/b.png", &png_bytes(2)),
                ("owned-again.png", &png_bytes(9)),
                ("notes.txt", b"kept"),
                (".trashed-c.png", &png_bytes(3)),
                ("nested.zip", &fs::read(&inner).unwrap()),
                ("__MACOSX/._a.png", b"resource fork"),
                (INBOX_ALBUM_MARKER, b"Hijacked"),
                ("day2/.photovault-album", b"Hijacked"),
            ],
        );
        let result = fixture.run(vec![zip_path.clone()], |_| {});
        assert_eq!((result.imported, result.skipped, result.failed), (2, 1, 0));
        assert!(!zip_path.exists());
        // Files that aren't imported stay behind; everything imported is gone.
        let folder = fixture.inbox.join("Summer Trip");
        assert_eq!(inbox_names(&fixture.inbox), ["Summer Trip"]);
        assert_eq!(
            inbox_names(&folder),
            [
                INBOX_ALBUM_MARKER,
                ".trashed-c.png",
                "nested.zip",
                "notes.txt"
            ]
        );
        assert_eq!(
            fs::read_to_string(folder.join(INBOX_ALBUM_MARKER)).unwrap(),
            "Summer Trip"
        );
        // A nested zip is not unpacked on later passes.
        let mut found = Vec::new();
        scan_inbox_media(&fixture.inbox, 0, &mut found);
        assert!(found.is_empty());
        {
            let vault = vlock(&fixture.state);
            assert_eq!(vault.albums.len(), 1);
            let (album, info) = vault.albums.iter().next().unwrap();
            assert_eq!(info.name, "Summer Trip");
            assert_eq!(vault.photos.len(), 3);
            // The duplicate of an owned photo is filed into the album too.
            assert!(vault.photos.values().all(|p| p.albums == [album.clone()]));
        }

        // A later zip with the same name (ignoring case) reuses the album, and
        // a folder left with nothing but its marker is removed.
        let again = fixture.inbox.join("summer trip.zip");
        write_zip(&again, &[("c.png", &png_bytes(4))]);
        let result = fixture.run(vec![again], |_| {});
        assert_eq!((result.imported, result.failed), (1, 0));
        assert_eq!(inbox_names(&fixture.inbox), ["Summer Trip"]);
        let vault = vlock(&fixture.state);
        assert_eq!(vault.albums.len(), 1);
        assert_eq!(vault.photos.len(), 4);
        assert!(vault.photos.values().all(|p| p.albums.len() == 1));
    }

    #[test]
    fn extracted_files_keep_the_archive_timestamp() {
        let fixture = ImportFixture::new();
        let zip_path = fixture.inbox.join("Dated.zip");
        let mut zip = zip::ZipWriter::new(fs::File::create(&zip_path).unwrap());
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
            + 86400;
        let entries = [
            ("a.png", 1_588_748_890u32),
            ("notes.txt", 1_588_748_890),
            ("later.txt", future),
        ];
        for (name, secs) in entries {
            let mut opts = zip::write::FullFileOptions::default();
            // Extended timestamp field: flags (modified time present), then UTC seconds.
            let mut field = vec![1u8];
            field.extend_from_slice(&secs.to_le_bytes());
            opts.add_extra_data(0x5455, field.into_boxed_slice(), false)
                .unwrap();
            zip.start_file(name, opts).unwrap();
            zip.write_all(&png_bytes(1)).unwrap();
        }
        zip.finish().unwrap();
        assert_eq!(fixture.run(vec![zip_path], |_| {}).imported, 1);
        let modified = |name: &str| {
            fs::metadata(fixture.inbox.join("Dated").join(name))
                .unwrap()
                .modified()
                .unwrap()
        };
        assert_eq!(
            modified("notes.txt"),
            UNIX_EPOCH + Duration::from_secs(1_588_748_890)
        );
        assert!(modified("later.txt") <= SystemTime::now());
    }

    #[test]
    fn zip_with_symlinks_or_a_replaced_path_is_kept() {
        let fixture = ImportFixture::new();
        let linked = fixture.inbox.join("Linked.zip");
        let mut zip = zip::ZipWriter::new(fs::File::create(&linked).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("a.png", opts).unwrap();
        zip.write_all(&png_bytes(1)).unwrap();
        zip.add_symlink("link.png", "a.png", opts).unwrap();
        zip.finish().unwrap();
        let result = fixture.run(vec![linked.clone()], |_| {});
        assert_eq!((result.imported, result.cleanup_failed), (1, 1));
        assert!(!result.issues[0].retryable);
        assert!(result.issues[0].reason.contains("symbolic links"));
        assert!(linked.exists());

        // A new zip saved at the same path during cleanup is left untouched.
        let replaced = fixture.inbox.join("Replaced.zip");
        write_zip(&replaced, &[("b.png", &png_bytes(2))]);
        let path = replaced.clone();
        AFTER_SOURCE_CLAIM.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || fs::write(path, b"newer zip").unwrap()))
        });
        let result = fixture.run(vec![replaced.clone()], |_| {});
        assert_eq!((result.imported, result.cleanup_failed), (1, 0));
        assert_eq!(fs::read(&replaced).unwrap(), b"newer zip");
    }

    #[test]
    fn manual_import_ignores_zips() {
        let fixture = ImportFixture::new();
        fixture.photo("a.png", 1);
        write_zip(&fixture.inbox.join("b.zip"), &[("c.png", &png_bytes(2))]);
        let found = collect_files(
            &[fixture.inbox.to_string_lossy().into_owned()],
            &mut ImportResult::default(),
        );
        assert_eq!(found, [fixture.inbox.join("a.png")]);
    }

    #[test]
    fn unusable_zips_are_kept_and_reported_without_writing_files() {
        let fixture = ImportFixture::new();
        let escaping = fixture.inbox.join("escaping.zip");
        write_zip(&escaping, &[("../evil.png", &png_bytes(1))]);
        let empty = fixture.inbox.join("documents.zip");
        write_zip(&empty, &[("notes.txt", b"not media")]);
        let broken = fixture.inbox.join("broken.zip");
        fs::write(&broken, b"not a zip").unwrap();
        let result = fixture.run(vec![escaping, empty, broken], |_| {});
        assert_eq!((result.imported, result.failed), (0, 3));
        assert!(result.issues.iter().all(|issue| !issue.retryable));
        assert!(result.issues[0].reason.contains("unsafe path"));
        assert!(result.issues[1].reason.contains("no photos or videos"));
        assert_eq!(
            inbox_names(&fixture.inbox),
            ["broken.zip", "documents.zip", "escaping.zip"]
        );
        assert!(!fixture.root.join("evil.png").exists());
        assert!(vlock(&fixture.state).albums.is_empty());
    }

    #[test]
    fn interrupted_extraction_staging_is_discarded() {
        let fixture = ImportFixture::new();
        let staging = fixture.inbox.join(format!("{UNZIP_STAGING_PREFIX}crashed"));
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("half.png"), b"partial").unwrap();
        let photo = fixture.photo("loose.png", 4);
        assert_eq!(fixture.run(vec![photo], |_| {}).imported, 1);
        assert!(inbox_names(&fixture.inbox).is_empty());
    }

    #[test]
    fn inbox_replacement_and_same_inode_edits_are_preserved() {
        for replace in [true, false] {
            let fixture = ImportFixture::new();
            let path = fixture.photo("source.png", 1);
            let (_, proof) = read_source(&path).unwrap();
            if replace {
                fs::remove_file(&path).unwrap();
            }
            fs::write(&path, b"changed source").unwrap();
            assert!(delete_inbox_source(&fixture.inbox, &path, &proof, &mut None).is_err());
            let mut found = Vec::new();
            scan_inbox_media(&fixture.inbox, 0, &mut found);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].0.file_name().unwrap(), "source.png");
            assert_eq!(fs::read(&found[0].0).unwrap(), b"changed source");
        }
    }

    #[test]
    fn inbox_replacement_after_claim_is_untouched() {
        let fixture = ImportFixture::new();
        let path = fixture.photo("source.png", 1);
        let (_, proof) = read_source(&path).unwrap();
        let replacement = path.clone();
        AFTER_SOURCE_CLAIM.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::write(replacement, b"new original pathname").unwrap();
            }))
        });
        delete_inbox_source(&fixture.inbox, &path, &proof, &mut None).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"new original pathname");
    }

    #[test]
    fn inbox_commits_and_cleans_both_new_and_duplicate_files() {
        let fixture = ImportFixture::new();
        let first = fixture.photo("first.png", 1);
        let second = fixture.photo("second.png", 1);
        let result = fixture.run(vec![first.clone(), second.clone()], |_| {});
        assert_eq!(
            (
                result.imported,
                result.skipped,
                result.failed,
                result.cleanup_failed
            ),
            (1, 1, 0, 0)
        );
        assert!(result.issues.is_empty());
        assert!(!first.exists() && !second.exists());
        assert_eq!(
            load_index(&vlock(&fixture.state), &fixture.key)
                .unwrap()
                .photos
                .len(),
            1
        );
    }

    #[test]
    fn replaced_duplicate_reports_cleanup_failure_and_preserves_new_bytes() {
        let fixture = ImportFixture::new();
        fixture.run(vec![fixture.photo("first.png", 1)], |_| {});
        let duplicate = fixture.photo("duplicate.png", 1);
        let vault = vlock(&fixture.state);
        let outcome = import_one(
            &fixture.key,
            &vault.objects_dir(),
            &duplicate,
            &mut existing_hashes(&vault),
            true,
        );
        drop(vault);
        let ImportOutcome::Skipped(id, proof) = outcome else {
            panic!("expected duplicate")
        };
        fs::remove_file(&duplicate).unwrap();
        fs::write(&duplicate, b"replacement").unwrap();
        let mut result = ImportResult::default();
        cleanup_inbox_source(
            &fixture.state,
            &fixture.inbox,
            &duplicate,
            &id,
            &proof,
            &mut result,
        );
        assert_eq!(result.cleanup_failed, 1);
        assert_eq!(result.issues[0].stage, "cleanup");
        let mut found = Vec::new();
        scan_inbox_media(&fixture.inbox, 0, &mut found);
        assert_eq!(fs::read(&found[0].0).unwrap(), b"replacement");
    }

    #[test]
    fn cleanup_failure_does_not_hide_successful_import() {
        let fixture = ImportFixture::new();
        let path = fixture.photo("source.png", 1);
        let original = fs::read(&path).unwrap();
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(fixture.inbox.clone()));
        let result = fixture.run(vec![path], |_| {});
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert_eq!(
            (result.imported, result.failed, result.cleanup_failed),
            (1, 0, 1)
        );
        assert!(result.issues[0].retryable);
        let mut found = Vec::new();
        scan_inbox_media(&fixture.inbox, 0, &mut found);
        assert_eq!(found.len(), 1);
        assert_eq!(result.issues[0].retry_path.as_ref(), Some(&found[0].0));
        let now = Instant::now();
        let retry = InboxRetry::record(found[0].1, None, true, false, now);
        assert!(!retry.ready(found[0].1, now));
        assert_eq!(fs::read(&found[0].0).unwrap(), original);
        let retried = fixture.run(vec![found[0].0.clone()], |_| {});
        assert_eq!(
            (retried.imported, retried.skipped, retried.cleanup_failed),
            (0, 1, 0)
        );
    }

    #[test]
    fn object_sync_failure_prevents_index_commit_and_retries_successfully() {
        let fixture = ImportFixture::new();
        let path = fixture.photo("source.png", 1);
        let objects = vlock(&fixture.state).objects_dir();
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(objects.clone()));
        let result = fixture.run(vec![path.clone()], |_| {});
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert_eq!((result.imported, result.failed), (0, 1));
        assert!(result.issues[0].retryable);
        assert!(path.exists());
        assert!(vlock(&fixture.state).photos.is_empty());
        assert!(!vlock(&fixture.state).index_path().exists());
        assert_eq!(fs::read_dir(objects).unwrap().count(), 0);
        let retried = fixture.run(vec![path.clone()], |_| {});
        assert_eq!((retried.imported, retried.failed), (1, 0));
        assert!(!path.exists());
    }

    #[test]
    fn failed_later_batch_retains_earlier_commits_and_remaining_sources() {
        let fixture = ImportFixture::new();
        let files: Vec<_> = (0..30)
            .map(|i| fixture.photo(&format!("{i}.png"), i))
            .collect();
        let index_tmp = vlock(&fixture.state).index_path().with_extension("tmp");
        // Block index saves once the first batch is saved.
        let result = fixture.run(files.clone(), |event| {
            if matches!(event, InboxEvent::LibraryChanged) {
                let _ = fs::create_dir(&index_tmp);
            }
        });
        assert_eq!(
            (result.imported, result.failed, result.cleanup_failed),
            (20, 10, 0)
        );
        assert_eq!(result.issues.len(), 10);
        assert_eq!(
            load_index(&vlock(&fixture.state), &fixture.key)
                .unwrap()
                .photos
                .len(),
            20
        );
        assert!(files[..20].iter().all(|path| !path.exists()));
        assert!(files[20..].iter().all(|path| path.exists()));
    }

    #[test]
    fn unreadable_and_bad_media_have_distinct_retry_policies() {
        let fixture = ImportFixture::new();
        let bad = fixture.inbox.join("bad.png");
        fs::write(&bad, b"not an image").unwrap();
        let missing = fixture.inbox.join("missing.png");
        let result = fixture.run(vec![bad.clone(), missing], |_| {});
        assert_eq!((result.imported, result.failed), (0, 2));
        assert!(!result.issues[0].retryable);
        assert!(result.issues[1].retryable);
        assert!(bad.exists());
    }

    #[test]
    fn retry_backoff_is_bounded_and_changed_files_retry_immediately() {
        let fixture = ImportFixture::new();
        let path = fixture.photo("source.png", 1);
        let sig = file_signature(&fs::metadata(&path).unwrap());
        let now = Instant::now();
        let mut retry = InboxRetry::record(sig, None, true, false, now);
        assert!(!retry.ready(sig, now));
        assert!(retry.ready(sig, now + Duration::from_secs(2)));
        for _ in 0..100 {
            retry = InboxRetry::record(sig, Some(&retry), true, false, now);
        }
        assert!(retry.ready(sig, now + Duration::from_secs(60)));
        // A full disk waits 10 minutes, then 30, so retries don't keep refilling it.
        let slow = InboxRetry::record(sig, None, true, true, now);
        assert!(!slow.ready(sig, now + Duration::from_secs(599)));
        assert!(slow.ready(sig, now + Duration::from_secs(600)));
        let slow = InboxRetry::record(sig, Some(&slow), true, true, now);
        assert!(!slow.ready(sig, now + Duration::from_secs(1799)));
        assert!(slow.ready(sig, now + Duration::from_secs(1800)));
        let permanent = InboxRetry::record(sig, None, false, false, now);
        assert!(!permanent.ready(sig, now + Duration::from_secs(86400)));
        fs::remove_file(&path).unwrap();
        fixture.photo("source.png", 2);
        let replaced = file_signature(&fs::metadata(path).unwrap());
        assert!(permanent.ready(replaced, now));
    }

    #[test]
    fn full_disk_zip_failures_retry_after_a_long_wait() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::StorageFull, ErrorKind::ReadOnlyFilesystem] {
            let failure = unzip_io_failure(Error::from(kind));
            assert!(failure.retryable && failure.slow_retry);
            assert!(failure.reason.ends_with("It will be retried later."));
        }
        for kind in [ErrorKind::InvalidFilename, ErrorKind::InvalidData] {
            let failure = unzip_io_failure(Error::from(kind));
            assert!(!failure.retryable && !failure.slow_retry);
        }
        assert!(!unzip_io_failure(Error::from(ErrorKind::Interrupted)).slow_retry);

        let path = PathBuf::from("/inbox/Trip.zip");
        let failure = unzip_io_failure(Error::from(ErrorKind::StorageFull));
        let mut result = ImportResult::default();
        result.issue(&path, failure.reason, "import", failure.retryable);
        result.issues[0].slow_retry = failure.slow_retry;
        let sig = (0, UNIX_EPOCH, 0, 0, 0, 0);
        let now = Instant::now();
        let (_, retry) = inbox_retry_after_failure(&path, sig, &result.issues[0], None, now);
        assert!(!retry.ready(sig, now + Duration::from_secs(60)));
        assert!(retry.ready(sig, now + Duration::from_secs(600)));
    }

    #[test]
    fn library_change_notifications_follow_index_saves() {
        let fixture = ImportFixture::new();
        let files: Vec<_> = (0..45)
            .map(|i| fixture.photo(&format!("{i:02}.png"), i))
            .collect();
        let mut saved = Vec::new();
        let mut progress = Vec::new();
        let result = fixture.run(files, |event| match event {
            InboxEvent::LibraryChanged => saved.push(
                load_index(&vlock(&fixture.state), &fixture.key)
                    .unwrap()
                    .photos
                    .len(),
            ),
            InboxEvent::Progress(p) => progress.push((p.done, p.total)),
        });
        assert_eq!(result.imported, 45);
        // One notification per committed batch, each after its save reached disk.
        assert_eq!(saved, [20, 40, 45]);
        assert_eq!(progress.first(), Some(&(0, 45)));
        assert_eq!(progress.last(), Some(&(45, 45)));
    }

    #[test]
    fn album_creation_and_filing_notify_library_changes() {
        let fixture = ImportFixture::new();
        let owned = fixture.inbox.join("owned.png");
        fs::write(&owned, png_bytes(1)).unwrap();
        let mut changes = 0;
        fixture.run(vec![owned], |event| {
            changes += matches!(event, InboxEvent::LibraryChanged) as usize;
        });
        assert_eq!(changes, 1);

        // A new album notifies once it's saved, then filing the duplicate into it.
        let zip_path = fixture.inbox.join("Trip.zip");
        write_zip(&zip_path, &[("a.png", &png_bytes(1))]);
        let mut saved_albums = Vec::new();
        fixture.run(vec![zip_path], |event| {
            if matches!(event, InboxEvent::LibraryChanged) {
                let index = load_index(&vlock(&fixture.state), &fixture.key).unwrap();
                let filed = index
                    .photos
                    .values()
                    .filter(|p| !p.albums.is_empty())
                    .count();
                saved_albums.push((index.albums.len(), filed));
            }
        });
        assert_eq!(saved_albums, [(1, 0), (1, 1)]);

        // Reusing the album doesn't notify; only the new photo's batch does.
        let again = fixture.inbox.join("trip.zip");
        write_zip(&again, &[("b.png", &png_bytes(2))]);
        let mut changes = 0;
        let result = fixture.run(vec![again], |event| {
            changes += matches!(event, InboxEvent::LibraryChanged) as usize;
        });
        assert_eq!((result.imported, changes), (1, 1));
        assert_eq!(vlock(&fixture.state).albums.len(), 1);
    }

    #[test]
    fn inbox_zips_are_imported_one_at_a_time() {
        let fixture = ImportFixture::new();
        let first = fixture.inbox.join("A.zip");
        let second = fixture.inbox.join("B.zip");
        write_zip(&first, &[("a.png", &png_bytes(1))]);
        write_zip(&second, &[("b.png", &png_bytes(2))]);
        let mut saved_before_unzip = Vec::new();
        let result = fixture.run(vec![first, second], |event| {
            if let InboxEvent::Progress(ImportProgress { total: 0, .. }) = event {
                saved_before_unzip.push(vlock(&fixture.state).photos.len());
            }
        });
        assert_eq!((result.imported, result.failed), (2, 0));
        // The first zip's photo is saved before the second zip is unpacked.
        assert_eq!(saved_before_unzip, [0, 1]);
    }

    #[test]
    fn zip_rewritten_in_place_during_cleanup_is_kept() {
        let fixture = ImportFixture::new();
        let zip_path = fixture.inbox.join("Rewritten.zip");
        write_zip(&zip_path, &[("a.png", &png_bytes(1))]);
        let inbox = fixture.inbox.clone();
        let rewritten = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let bytes = rewritten.clone();
        AFTER_SOURCE_CLAIM.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                // Same inode and size with the mtime restored: only the contents differ.
                let claimed = fs::read_dir(&inbox)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| p.to_string_lossy().contains("Pending import"))
                    .unwrap()
                    .join("Rewritten.zip");
                let modified = fs::metadata(&claimed).unwrap().modified().unwrap();
                let mut data = fs::read(&claimed).unwrap();
                data[0] ^= 0xff;
                let mut file = fs::OpenOptions::new().write(true).open(&claimed).unwrap();
                file.write_all(&data).unwrap();
                file.set_modified(modified).unwrap();
                *bytes.borrow_mut() = data;
            }))
        });
        let result = fixture.run(vec![zip_path], |_| {});
        assert_eq!((result.imported, result.cleanup_failed), (1, 1));
        assert!(result.issues[0].reason.contains("Archive changed"));
        let kept = result.issues[0].retry_path.as_ref().unwrap();
        assert_eq!(fs::read(kept).unwrap(), *rewritten.borrow());
    }

    #[test]
    fn selected_missing_paths_report_discovery_failures() {
        let fixture = ImportFixture::new();
        let missing = fixture.inbox.join("missing.png");
        let mut result = ImportResult::default();
        let files = collect_files(&[missing.to_string_lossy().into_owned()], &mut result);
        assert!(files.is_empty());
        assert_eq!(result.failed, 1);
        assert!(result.issues[0].retryable);
    }

    #[test]
    fn failed_album_assignment_restores_memory() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        vault.photos.insert("photo".into(), test_photo(None));
        vault.albums.insert(
            "album".into(),
            Album {
                name: "Trip".into(),
                created: 1.0,
            },
        );
        fs::create_dir(vault.index_path().with_extension("tmp")).unwrap();
        drop(vault);
        assert!(file_existing_into_album(&fixture.state, &["photo".into()], "album").is_err());
        assert!(vlock(&fixture.state).photos["photo"].albums.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn native_conversion_failures_remain_retryable() {
        use std::os::unix::process::ExitStatusExt;
        let fixture = ImportFixture::new();
        let output = fixture.root.join("missing-conversion.jpg");
        for status in [
            None,
            Some(std::process::ExitStatus::from_raw(256)),
            Some(std::process::ExitStatus::from_raw(0)),
        ] {
            assert!(
                converted_image_output(status, &output)
                    .unwrap_err()
                    .retryable
            );
        }
    }

    #[test]
    fn replacement_does_not_inherit_permanent_failure_after_processing() {
        let fixture = ImportFixture::new();
        let path = fixture.inbox.join("source.png");
        fs::write(&path, b"invalid image").unwrap();
        let signature = file_signature(&fs::metadata(&path).unwrap());
        let result = fixture.run(vec![path.clone()], |_| {});
        assert!(!result.issues[0].retryable);
        fs::remove_file(&path).unwrap();
        fixture.photo("source.png", 1);
        let replacement_signature = file_signature(&fs::metadata(&path).unwrap());
        let (_, retry) =
            inbox_retry_after_failure(&path, signature, &result.issues[0], None, Instant::now());
        assert!(retry.ready(replacement_signature, Instant::now()));
    }

    #[test]
    fn failed_import_batch_reports_unfiled_duplicate_album_assignment() {
        let fixture = ImportFixture::new();
        fixture.run(vec![fixture.photo("original.png", 200)], |_| {});
        let mut vault = vlock(&fixture.state);
        vault.albums.insert(
            "album".into(),
            Album {
                name: "Trip".into(),
                created: 1.0,
            },
        );
        persist_index(&vault, &fixture.key).unwrap();
        let hashes = existing_hashes(&vault);
        let objects = vault.objects_dir();
        let index_tmp = vault.index_path().with_extension("tmp");
        drop(vault);
        let mut files = vec![fixture.photo("duplicate.png", 200)];
        files.extend((0..100).map(|i| fixture.photo(&format!("new-{i}.png"), i)));
        let result = run_import(
            files,
            fixture.key,
            objects,
            hashes,
            true,
            Some("album".into()),
            |progress| {
                if progress.done == 100 {
                    fs::create_dir(&index_tmp).unwrap();
                }
            },
            &fixture.state,
        )
        .unwrap();
        assert_eq!(
            (result.imported, result.skipped, result.failed),
            (0, 0, 101)
        );
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.name.ends_with("duplicate.png") && issue.reason.contains("album")));
        assert!(vlock(&fixture.state)
            .photos
            .values()
            .all(|photo| photo.albums.is_empty()));
    }

    #[test]
    fn deletion_state_rolls_back_when_index_cannot_be_saved() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        vault.photos.insert("live".into(), test_photo(None));
        vault
            .photos
            .insert("deleted".into(), test_photo(Some(12.0)));
        persist_index(&vault, &fixture.key).unwrap();
        fs::create_dir(vault.index_path().with_extension("tmp")).unwrap();
        let ids = vec!["live".into(), "deleted".into(), "live".into()];
        for deleted in [Some(30.0), None] {
            assert!(set_deleted(&mut vault, &fixture.key, &ids, deleted).is_err());
            assert_eq!(vault.photos["live"].deleted, None);
            assert_eq!(vault.photos["deleted"].deleted, Some(12.0));
            let index = load_index(&vault, &fixture.key).unwrap();
            assert_eq!(index.photos["live"].deleted, None);
            assert_eq!(index.photos["deleted"].deleted, Some(12.0));
        }
    }

    #[test]
    fn deletion_state_persists_trash_and_restore() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        vault.photos.insert("photo".into(), test_photo(None));
        for deleted in [Some(30.0), None] {
            set_deleted(&mut vault, &fixture.key, &["photo".into()], deleted).unwrap();
            assert_eq!(
                load_index(&vault, &fixture.key).unwrap().photos["photo"].deleted,
                deleted
            );
        }
    }

    #[test]
    fn bulk_export_reports_read_decrypt_and_write_failures_without_losing_successes() {
        let fixture = ImportFixture::new();
        let objects = vlock(&fixture.state).objects_dir();
        let destination = fixture.root.join("export");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("same.jpg"), b"existing").unwrap();
        fs::write(
            objects.join("good"),
            encrypt(&fixture.key, b"original").unwrap(),
        )
        .unwrap();
        fs::write(objects.join("corrupt"), b"corrupt").unwrap();
        fs::write(
            objects.join("long"),
            encrypt(&fixture.key, b"long").unwrap(),
        )
        .unwrap();
        let entries = vec![
            ("good".into(), "same.jpg".into()),
            ("missing".into(), "missing.jpg".into()),
            ("corrupt".into(), "corrupt.jpg".into()),
            ("long".into(), format!("{}.jpg", "x".repeat(300))),
        ];
        let result = export_entries(
            &fixture.key,
            &objects,
            &destination,
            &entries,
            ExportResult::default(),
            |_| {},
        );
        assert_eq!((result.exported, result.failed), (1, 3));
        assert!(result.issues[0].reason.contains("read"));
        assert!(result.issues[1].reason.contains("decrypt"));
        assert!(result.issues[2].reason.contains("create"));
        assert_eq!(fs::read(destination.join("same.jpg")).unwrap(), b"existing");
        assert_eq!(
            fs::read(destination.join("same (1).jpg")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn bulk_export_reports_every_file_when_destination_is_unusable() {
        let fixture = ImportFixture::new();
        let destination = fixture.root.join("not-a-directory");
        fs::write(&destination, b"keep").unwrap();
        let entries = vec![("a".into(), "a.jpg".into()), ("b".into(), "b.jpg".into())];
        let result = export_entries(
            &fixture.key,
            &fixture.root,
            &destination,
            &entries,
            ExportResult::default(),
            |_| {},
        );
        assert_eq!((result.exported, result.failed), (0, 2));
        assert!(result
            .issues
            .iter()
            .all(|issue| issue.reason.contains("export folder")));
        assert_eq!(fs::read(destination).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn export_destination_does_not_reuse_a_dangling_symlink() {
        let fixture = ImportFixture::new();
        let directory = fixture.root.join("export");
        fs::create_dir(&directory).unwrap();
        std::os::unix::fs::symlink(fixture.root.join("missing"), directory.join("photo.jpg"))
            .unwrap();
        assert_eq!(
            unique_dest(&directory, "photo.jpg"),
            directory.join("photo (1).jpg")
        );
        write_export(&directory, "photo.jpg", b"exported").unwrap();
        assert!(!fixture.root.join("missing").exists());
        assert_eq!(
            fs::read(directory.join("photo (1).jpg")).unwrap(),
            b"exported"
        );
    }

    #[test]
    fn clearing_vault_rolls_back_photos_and_albums_before_removing_objects() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        vault.photos.insert("photo".into(), test_photo(None));
        vault.albums.insert(
            "album".into(),
            Album {
                name: "Trip".into(),
                created: 1.0,
            },
        );
        vault.media_cache = Some(("photo".into(), Arc::new(vec![1, 2, 3])));
        let object = vault.objects_dir().join("photo");
        fs::write(&object, b"encrypted original").unwrap();
        persist_index(&vault, &fixture.key).unwrap();
        fs::create_dir(vault.index_path().with_extension("tmp")).unwrap();
        assert!(clear_vault_contents(&mut vault, &fixture.key).is_err());
        assert!(vault.photos.contains_key("photo"));
        assert!(vault.albums.contains_key("album"));
        assert!(vault.media_cache.is_some());
        assert_eq!(fs::read(object).unwrap(), b"encrypted original");
        assert_eq!(load_index(&vault, &fixture.key).unwrap().photos.len(), 1);
    }

    #[test]
    fn partial_export_write_is_reported_and_retry_preserves_existing_output() {
        let fixture = ImportFixture::new();
        let objects = vlock(&fixture.state).objects_dir();
        let destination = fixture.root.join("export");
        fs::write(
            objects.join("photo"),
            encrypt(&fixture.key, b"original").unwrap(),
        )
        .unwrap();
        let entries = vec![("photo".into(), "photo.jpg".into())];
        FAIL_EXPORT_WRITE.with(|fail| fail.set(true));
        let failed = export_entries(
            &fixture.key,
            &objects,
            &destination,
            &entries,
            ExportResult::default(),
            |_| {},
        );
        assert_eq!((failed.exported, failed.failed), (0, 1));
        assert_eq!(failed.issues[0].name, "photo.jpg");
        assert!(failed.issues[0].reason.contains("incomplete output"));
        assert_eq!(fs::read(destination.join("photo.jpg")).unwrap(), b"o");
        let retried = export_entries(
            &fixture.key,
            &objects,
            &destination,
            &entries,
            ExportResult::default(),
            |_| {},
        );
        assert_eq!((retried.exported, retried.failed), (1, 0));
        assert_eq!(fs::read(destination.join("photo.jpg")).unwrap(), b"o");
        assert_eq!(
            fs::read(destination.join("photo (1).jpg")).unwrap(),
            b"original"
        );
    }

    fn fail_sync_after_index_replacement(dir: PathBuf) {
        AFTER_INDEX_REPLACEMENT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(dir));
            }))
        });
    }

    #[test]
    fn post_rename_sync_failure_restores_trash_and_restore_after_restart() {
        for original in [None, Some(now_secs())] {
            let fixture = ImportFixture::new();
            let mut vault = vlock(&fixture.state);
            vault.photos.insert("photo".into(), test_photo(original));
            persist_index(&vault, &fixture.key).unwrap();
            let requested = if original.is_some() {
                None
            } else {
                Some(now_secs())
            };
            fail_sync_after_index_replacement(vault.dir.clone());
            assert!(set_deleted(&mut vault, &fixture.key, &["photo".into()], requested).is_err());
            assert_eq!(vault.photos["photo"].deleted, original);
            assert!(vault.dir.join("index.rollback").exists());
            let proposed = parse_index(
                &decrypt(&fixture.key, &fs::read(vault.index_path()).unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(proposed.photos["photo"].deleted, requested);
            assert!(persist_index(&vault, &fixture.key).is_err());
            assert!(load_index(&vault, &fixture.key).is_err());
            FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
            let restarted = Mutex::new(test_vault(vault.dir.clone(), None));
            drop(vault);
            finish_unlock(&restarted, fixture.key).unwrap();
            let recovered = vlock(&restarted);
            assert_eq!(recovered.photos["photo"].deleted, original);
            assert!(recovered.recovery_required);
            assert!(!recovered.dir.join("index.rollback").exists());
            assert!(recovered.dir.join("index.unconfirmed").exists());
        }
    }

    #[test]
    fn post_rename_sync_failure_of_delete_all_preserves_library_and_objects() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        vault.photos.insert("photo".into(), test_photo(None));
        vault.albums.insert(
            "album".into(),
            Album {
                name: "Trip".into(),
                created: 1.0,
            },
        );
        let object = vault.objects_dir().join("photo");
        fs::write(&object, b"encrypted original").unwrap();
        persist_index(&vault, &fixture.key).unwrap();
        fail_sync_after_index_replacement(vault.dir.clone());
        assert!(clear_vault_contents(&mut vault, &fixture.key).is_err());
        assert!(vault.photos.contains_key("photo"));
        assert!(vault.albums.contains_key("album"));
        assert!(load_index(&vault, &fixture.key).is_err());
        assert_eq!(fs::read(&object).unwrap(), b"encrypted original");
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        let restarted = Mutex::new(test_vault(vault.dir.clone(), None));
        drop(vault);
        finish_unlock(&restarted, fixture.key).unwrap();
        let recovered = vlock(&restarted);
        assert!(recovered.photos.contains_key("photo"));
        assert!(recovered.albums.contains_key("album"));
        assert_eq!(sweep_orphans(&recovered), 0);
        assert_eq!(fs::read(object).unwrap(), b"encrypted original");
    }

    #[test]
    fn first_index_post_rename_sync_failure_recovers_an_empty_prior_library() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        vault.photos.insert("new".into(), test_photo(None));
        fail_sync_after_index_replacement(vault.dir.clone());
        assert!(persist_index(&vault, &fixture.key).is_err());
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        let restored = load_index(&vault, &fixture.key).unwrap();
        assert!(restored.photos.is_empty());
        assert!(restored.recovery_required);
        assert!(vault.dir.join("index.unconfirmed").exists());
    }

    #[test]
    fn background_claims_do_not_hold_off_auto_lock() {
        let idle_vault = |idle_secs: u64| {
            let mut vault = test_vault(PathBuf::new(), Some(random_key()));
            vault.settings.auto_lock_secs = 60;
            vault.last_activity = Instant::now()
                .checked_sub(Duration::from_secs(idle_secs))
                .unwrap();
            let since = vault.last_activity;
            (Mutex::new(vault), since)
        };

        let (state, since) = idle_vault(120);
        assert!(claim_background_import(&state).is_err());
        {
            let mut vault = vlock(&state);
            assert_eq!(vault.last_activity, since);
            assert!(!vault.importing);
            // lock_timer's check, and any later user check, locks it.
            assert!(vault.idle_too_long());
            assert!(vault.active_key().is_none());
            assert!(vault.key.is_none());
        }

        let (state, since) = idle_vault(30);
        drop(claim_background_import(&state).unwrap());
        assert_eq!(vlock(&state).last_activity, since);
        drop(claim_import(&state).unwrap());
        assert!(vlock(&state).last_activity > since);

        let (state, _) = idle_vault(120);
        assert!(claim_import(&state).is_err());
        assert!(vlock(&state).key.is_none());
    }

    fn library_json(
        photos: &HashMap<String, PhotoInfo>,
        albums: &HashMap<String, Album>,
    ) -> serde_json::Value {
        serde_json::to_value(IndexOut {
            photos,
            albums,
            recovery_required: false,
        })
        .unwrap()
    }

    #[test]
    fn failed_library_edits_restore_memory() {
        let fixture = ImportFixture::new();
        let key = fixture.key;
        let mut vault = vlock(&fixture.state);
        let mut photo = test_photo(None);
        photo.albums = vec!["album".into()];
        photo.tags = vec!["beach".into()];
        vault.photos.insert("photo".into(), photo);
        vault.photos.insert("other".into(), test_photo(None));
        for id in ["album", "empty"] {
            vault.albums.insert(
                id.into(),
                Album {
                    name: id.into(),
                    created: 1.0,
                },
            );
        }
        persist_index(&vault, &key).unwrap();
        let before = library_json(&vault.photos, &vault.albums);
        let index_tmp = vault.index_path().with_extension("tmp");
        fs::create_dir(&index_tmp).unwrap();
        let ids = vec!["photo".to_string(), "other".to_string()];
        let edits: Vec<(&str, Box<dyn Fn(&mut Vault) -> Result<(), String>>)> = vec![
            ("album create", Box::new(|v| create_album(v, &key, "New".into()).map(|_| ()))),
            ("album delete", Box::new(|v| delete_album(v, &key, "album"))),
            ("assign", Box::new(|v| assign_album(v, &key, &ids, "empty", true))),
            ("unassign", Box::new(|v| assign_album(v, &key, &ids, "album", false))),
            ("favorite", Box::new(|v| mark_favorite(v, &key, &ids, true))),
            ("tags", Box::new(|v| set_photo_tags(v, &key, "photo", vec!["new".into()]))),
        ];
        for (name, edit) in &edits {
            assert!(edit(&mut vault).is_err(), "{name} should fail");
            assert_eq!(library_json(&vault.photos, &vault.albums), before, "{name}");
        }
        // A later successful save must not carry any of the failed edits.
        fs::remove_dir(&index_tmp).unwrap();
        persist_index(&vault, &key).unwrap();
        let index = load_index(&vault, &key).unwrap();
        assert_eq!(library_json(&index.photos, &index.albums), before);
        mark_favorite(&mut vault, &key, &ids, true).unwrap();
        assert!(load_index(&vault, &key).unwrap().photos["photo"].favorite);
    }

    #[test]
    fn interrupted_library_save_restores_memory_and_recovers_after_restart() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        vault.photos.insert("photo".into(), test_photo(None));
        persist_index(&vault, &fixture.key).unwrap();
        fail_sync_after_index_replacement(vault.dir.clone());
        assert!(mark_favorite(&mut vault, &fixture.key, &["photo".into()], true).is_err());
        assert!(!vault.photos["photo"].favorite);
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        let restarted = Mutex::new(test_vault(vault.dir.clone(), None));
        drop(vault);
        finish_unlock(&restarted, fixture.key).unwrap();
        assert!(!vlock(&restarted).photos["photo"].favorite);
    }

    #[test]
    fn in_place_crypto_matches_the_object_format() {
        let key = random_key();
        let blob = encrypt_owned(&key, b"hello".to_vec()).unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), b"hello");
        assert_eq!(
            decrypt_owned(&key, encrypt(&key, b"world").unwrap()).unwrap(),
            b"world"
        );
        let mut tampered = blob.clone();
        tampered[14] ^= 1;
        assert!(decrypt_owned(&key, tampered).is_err());
        assert!(decrypt_owned(&random_key(), blob).is_err());
        assert!(decrypt_owned(&key, vec![0; 12]).is_err());
    }

    #[test]
    fn streamed_source_check_matches_full_read() {
        let fixture = ImportFixture::new();
        let path = fixture.photo("photo.png", 7);
        let (data, proof) = read_source(&path).unwrap();
        assert!(data.capacity() >= data.len() + ENCRYPTION_OVERHEAD);
        let streamed = hash_source(&path).unwrap();
        assert_eq!(streamed.hash, proof.hash);
        assert!(same_source(&proof.metadata, &streamed.metadata));
    }

    #[test]
    fn files_over_the_import_cap_fail_permanently_without_being_read() {
        let fixture = ImportFixture::new();
        // Sparse: no real disk space is used.
        let at_cap = fixture.inbox.join("at-cap.mov");
        fs::File::create(&at_cap).unwrap().set_len(MAX_IMPORT_BYTES).unwrap();
        let proof = scan_source(&at_cap, |_, len| {
            assert_eq!(len, MAX_IMPORT_BYTES);
            Ok(blake3::hash(b""))
        });
        assert!(proof.is_ok());
        fs::remove_file(&at_cap).unwrap();

        let huge = fixture.inbox.join("huge.mov");
        fs::File::create(&huge).unwrap().set_len(MAX_IMPORT_BYTES + 1).unwrap();
        let Err(failure) = hash_source(&huge) else {
            panic!("an oversized file was accepted");
        };
        assert!(!failure.retryable);
        assert_eq!(
            failure.reason,
            "File is larger than 4 GB, which PhotoVault can't import yet."
        );

        // Inbox: reported as permanent, so the watcher doesn't retry it.
        let signature = file_signature(&fs::metadata(&huge).unwrap());
        let result = fixture.run(vec![huge.clone()], |_| {});
        assert_eq!((result.imported, result.failed), (0, 1));
        assert!(!result.issues[0].retryable);
        assert!(result.issues[0].reason.contains("larger than 4 GB"));
        let (_, retry) =
            inbox_retry_after_failure(&huge, signature, &result.issues[0], None, Instant::now());
        assert!(!retry.ready(signature, Instant::now() + Duration::from_secs(3600)));

        // Manual import.
        let objects = vlock(&fixture.state).objects_dir();
        let manual = run_import(
            vec![huge.clone()],
            fixture.key,
            objects.clone(),
            HashMap::new(),
            true,
            None,
            |_| {},
            &fixture.state,
        )
        .unwrap();
        assert_eq!((manual.imported, manual.failed), (0, 1));
        assert!(!manual.issues[0].retryable);
        assert!(huge.exists());
        assert!(vlock(&fixture.state).photos.is_empty());
        assert_eq!(fs::read_dir(objects).unwrap().count(), 0);
    }

    #[test]
    fn background_saves_and_refreshes_do_not_hold_off_auto_lock() {
        let fixture = ImportFixture::new();
        let ago = |secs| Instant::now().checked_sub(Duration::from_secs(secs)).unwrap();
        let since = ago(30);
        {
            let mut vault = vlock(&fixture.state);
            vault.settings.auto_lock_secs = 60;
            vault.last_activity = since;
        }
        // Refreshing the lists and thumbnails doesn't count as use. Opening
        // full media (like playing a video) does.
        photo_list(&fixture.state).unwrap();
        album_list(&fixture.state).unwrap();
        assert!(media_key(&mut vlock(&fixture.state), true).is_some());
        assert_eq!(vlock(&fixture.state).last_activity, since);
        assert!(media_key(&mut vlock(&fixture.state), false).is_some());
        assert!(vlock(&fixture.state).last_activity > since);

        // A watcher pass whose index save fails, outlasting the auto-lock time.
        vlock(&fixture.state).last_activity = since;
        let photo = fixture.photo("a.png", 1);
        let index_tmp = vlock(&fixture.state).index_path().with_extension("tmp");
        fs::create_dir(&index_tmp).unwrap();
        let guard = claim_background_import(&fixture.state).unwrap();
        let since = ago(120);
        vlock(&fixture.state).last_activity = since;
        let result = fixture.run(vec![photo.clone()], |_| {});
        assert_eq!((result.imported, result.failed), (0, 1));
        assert!(photo.exists());
        drop(guard);

        // The UI refreshes after the pass. Those reads see a locked vault and
        // leave it idle, so lock_timer locks it and tells the UI.
        assert_eq!(photo_list(&fixture.state).err().as_deref(), Some("locked"));
        assert_eq!(album_list(&fixture.state).err().as_deref(), Some("locked"));
        assert!(media_key(&mut vlock(&fixture.state), true).is_none());
        let vault = vlock(&fixture.state);
        assert_eq!(vault.last_activity, since);
        assert!(vault.key.is_some());
        assert!(vault.idle_too_long());
    }

    #[test]
    fn index_save_failure_leaves_later_zips_untouched() {
        // First the new album can't be saved, then filing a duplicate into an
        // existing album can't be saved.
        for album_exists in [false, true] {
            let fixture = ImportFixture::new();
            if album_exists {
                let owned = fixture.inbox.join("owned.png");
                fs::write(&owned, png_bytes(1)).unwrap();
                assert_eq!(fixture.run(vec![owned], |_| {}).imported, 1);
                ensure_album(&fixture.state, "A").unwrap();
            }
            let first = fixture.inbox.join("A.zip");
            let second = fixture.inbox.join("B.zip");
            write_zip(&first, &[("a.png", &png_bytes(1))]);
            write_zip(&second, &[("b.png", &png_bytes(2))]);
            let index_tmp = vlock(&fixture.state).index_path().with_extension("tmp");
            fs::create_dir(&index_tmp).unwrap();
            let result = fixture.run(vec![first, second.clone()], |_| {});
            assert_eq!(result.imported, 0, "album exists: {album_exists}");
            assert!(second.exists(), "album exists: {album_exists}");
            assert!(!fixture.inbox.join("B").exists(), "album exists: {album_exists}");
            let issue = result
                .issues
                .iter()
                .find(|issue| issue.name == second.to_string_lossy())
                .unwrap();
            assert_eq!(
                issue.reason,
                "Not attempted because the index could not be saved."
            );
            assert!(issue.retryable);
        }
    }

    fn blank_meta() -> Meta {
        Meta {
            salt: String::new(),
            verifier: String::new(),
            n: LEGACY_SCRYPT_LOG_N,
            r: DEFAULT_SCRYPT_R,
            p: DEFAULT_SCRYPT_P,
            wrapped_master: None,
            recovery: None,
        }
    }

    /// Whether the recovery key in meta.json is this one.
    fn recovery_opens(dir: &std::path::Path, key: &[u8; 32], text: &str) -> bool {
        let wrapped = hex::decode(read_meta(dir).unwrap().recovery.unwrap()).unwrap();
        decrypt(&parse_recovery_key(text).unwrap(), &wrapped).is_ok_and(|m| m == key)
    }

    #[test]
    fn recovery_key_is_saved_only_after_it_is_confirmed() {
        let fixture = ImportFixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        let opens = |text: &str| recovery_opens(&dir, &fixture.key, text);
        let mut meta = blank_meta();
        rewrap_master(&mut meta, "first password", &fixture.key).unwrap();
        let old = random_key();
        meta.recovery = Some(hex::encode(encrypt(&old, &fixture.key).unwrap()));
        write_meta(&dir, &meta).unwrap();
        persist_index(&vlock(&fixture.state), &fixture.key).unwrap();
        let old = format_recovery_key(&old);

        // Generated but not confirmed: only the old key opens the vault.
        let shown = generate_recovery_key(&fixture.state).unwrap();
        assert!(opens(&old) && !opens(&shown.key));

        // Locking drops the new key, so confirming fails and the old key still unlocks.
        wipe_vault(&mut vlock(&fixture.state));
        assert!(confirm_recovery_key(&fixture.state, &shown.id).is_err());
        assert!(opens(&old) && !opens(&shown.key));
        unlock_with_recovery_key(&old, "second password", &fixture.state).unwrap();
        assert!(vlock(&fixture.state).key.is_some());
        assert!(confirm_recovery_key(&fixture.state, &shown.id).is_err());

        // Done on a replaced key fails and writes nothing, even though a newer
        // key is waiting. Done on the shown key saves it and retires the old one.
        let replaced = generate_recovery_key(&fixture.state).unwrap();
        let latest = generate_recovery_key(&fixture.state).unwrap();
        let files = || (fs::read(dir.join("meta.json")).unwrap(), fs::read(dir.join("meta.bak")).unwrap());
        let before = files();
        assert!(confirm_recovery_key(&fixture.state, &replaced.id).is_err());
        assert_eq!(files(), before);
        assert!(vlock(&fixture.state).pending_recovery.is_some());
        let confirmed = confirm_recovery_key(&fixture.state, &latest.id).unwrap();
        assert!(confirmed.warning.is_none());
        assert!(opens(&latest.key) && !opens(&replaced.key) && !opens(&old));
        assert!(vlock(&fixture.state).pending_recovery.is_none());
        assert!(confirm_recovery_key(&fixture.state, &latest.id).is_err());
    }

    #[test]
    fn recovery_confirm_that_waited_across_a_lock_and_unlock_saves_nothing() {
        let fixture = ImportFixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        write_meta(&dir, &blank_meta()).unwrap();
        persist_index(&vlock(&fixture.state), &fixture.key).unwrap();
        let shown = generate_recovery_key(&fixture.state).unwrap();
        let meta_mutex = vlock(&fixture.state).meta_lock.clone();
        let meta_guard = meta_lock(&meta_mutex);
        std::thread::scope(|scope| {
            let confirming = scope.spawn(|| confirm_recovery_key(&fixture.state, &shown.id));
            // The confirm clones the meta lock while it reads the session, then waits.
            while Arc::strong_count(&meta_mutex) < 3 {
                std::thread::yield_now();
            }
            wipe_vault(&mut vlock(&fixture.state));
            finish_unlock(&fixture.state, fixture.key).unwrap();
            // Unlock restores the same master key. Even a pending key with the
            // same id belongs to the new session, so the old confirm can't save it.
            vlock(&fixture.state).pending_recovery = Some((shown.id.clone(), Zeroizing::new(random_key())));
            drop(meta_guard);
            assert!(confirming.join().unwrap().is_err());
        });
        assert!(read_meta(&dir).unwrap().recovery.is_none());
        assert!(vlock(&fixture.state).pending_recovery.is_some());
    }

    #[test]
    fn recovery_confirm_reports_whether_the_new_key_replaced_the_old_one() {
        let fixture = ImportFixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        let opens = |text: &str| recovery_opens(&dir, &fixture.key, text);
        let old = random_key();
        let mut meta = blank_meta();
        meta.recovery = Some(hex::encode(encrypt(&old, &fixture.key).unwrap()));
        write_meta(&dir, &meta).unwrap();
        let old = format_recovery_key(&old);
        let shown = generate_recovery_key(&fixture.state).unwrap();

        // The backup's sync fails before meta.json is touched: an error, and the
        // old key still works.
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(dir.clone()));
        assert!(confirm_recovery_key(&fixture.state, &shown.id).is_err());
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert!(opens(&old) && !opens(&shown.key));
        assert!(vlock(&fixture.state).pending_recovery.is_some());

        // The sync fails after meta.json is replaced: the new key is the one
        // that works, so it's saved with a warning and no longer pending.
        FAIL_SYNC_AFTER_REPLACING.with(|path| *path.borrow_mut() = Some(dir.join("meta.json")));
        let confirmed = confirm_recovery_key(&fixture.state, &shown.id).unwrap();
        FAIL_SYNC_AFTER_REPLACING.with(|path| path.borrow_mut().take());
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert!(confirmed.warning.unwrap().contains("keep any old key until"));
        assert!(opens(&shown.key) && !opens(&old));
        assert!(vlock(&fixture.state).pending_recovery.is_none());

        // meta.json is unreadable, so readers use meta.bak. Once the new key
        // replaces the backup, it's the one that works, even if the sync fails.
        let old = shown.key;
        fs::write(dir.join("meta.json"), b"truncated").unwrap();
        let shown = generate_recovery_key(&fixture.state).unwrap();
        let confirmed = with_failed_sync_after(&dir, "meta.bak", || confirm_recovery_key(&fixture.state, &shown.id));
        assert!(confirmed.unwrap().warning.is_some());
        assert!(opens(&shown.key) && !opens(&old));
        assert!(vlock(&fixture.state).pending_recovery.is_none());
    }

    /// Run `f` while the directory sync after replacing `dir/name` fails.
    fn with_failed_sync_after<T>(dir: &std::path::Path, name: &str, f: impl FnOnce() -> T) -> T {
        FAIL_SYNC_AFTER_REPLACING.with(|path| *path.borrow_mut() = Some(dir.join(name)));
        let result = f();
        FAIL_SYNC_AFTER_REPLACING.with(|path| path.borrow_mut().take());
        let failed = FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert_eq!(failed.as_deref(), Some(dir), "the write never replaced {name}");
        result
    }

    /// A vault in the fixture with this password and recovery key, locked.
    fn locked_vault(fixture: &ImportFixture, password: &str, recovery: &[u8; 32]) -> PathBuf {
        let dir = vlock(&fixture.state).dir.clone();
        let mut meta = blank_meta();
        rewrap_master(&mut meta, password, &fixture.key).unwrap();
        meta.recovery = Some(hex::encode(encrypt(recovery, &fixture.key).unwrap()));
        write_meta(&dir, &meta).unwrap();
        persist_index(&vlock(&fixture.state), &fixture.key).unwrap();
        wipe_vault(&mut vlock(&fixture.state));
        dir
    }

    fn password_opens(dir: &std::path::Path, password: &str) -> bool {
        master_from_password(password, &read_meta(dir).unwrap()).is_ok()
    }

    #[test]
    fn password_change_counts_once_the_new_meta_is_in_place() {
        let fixture = ImportFixture::new();
        let dir = locked_vault(&fixture, "old password", &random_key());
        unlock_with_password(&fixture.state, "old password").unwrap();

        // Nothing replaced: an error, and the old password still works.
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(dir.clone()));
        let failed = change_vault_password(&fixture.state, "old password", "new password");
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert!(failed.is_err());
        assert!(password_opens(&dir, "old password") && !password_opens(&dir, "new password"));

        // meta.json was replaced but not synced: the new password is the one
        // that works, so the change succeeds with a warning.
        let saved = with_failed_sync_after(&dir, "meta.json", || {
            change_vault_password(&fixture.state, "old password", "new password")
        });
        assert!(saved.unwrap().warning.unwrap().contains("Use your new password"));
        assert!(password_opens(&dir, "new password") && !password_opens(&dir, "old password"));
        wipe_vault(&mut vlock(&fixture.state));
        unlock_with_password(&fixture.state, "new password").unwrap();
    }

    #[test]
    fn recovery_reset_unlocks_once_the_new_password_is_in_place() {
        let fixture = ImportFixture::new();
        let rk = random_key();
        let dir = locked_vault(&fixture, "old password", &rk);
        let saved = with_failed_sync_after(&dir, "meta.json", || {
            unlock_with_recovery_key(&format_recovery_key(&rk), "new password", &fixture.state)
        });
        assert!(saved.unwrap().warning.unwrap().contains("Use your new password"));
        assert_eq!(vlock(&fixture.state).key, Some(fixture.key));
        assert!(password_opens(&dir, "new password") && !password_opens(&dir, "old password"));
    }

    #[test]
    fn recovery_disable_counts_once_the_new_meta_is_in_place() {
        let fixture = ImportFixture::new();
        let rk = format_recovery_key(&random_key());
        let dir = locked_vault(&fixture, "password", &parse_recovery_key(&rk).unwrap());
        unlock_with_password(&fixture.state, "password").unwrap();
        let saved = with_failed_sync_after(&dir, "meta.json", || disable_recovery_key(&fixture.state));
        assert!(saved.unwrap().warning.unwrap().contains("turn it off again"));
        assert!(read_meta(&dir).unwrap().recovery.is_none());
        wipe_vault(&mut vlock(&fixture.state));
        let reset = unlock_with_recovery_key(&rk, "new password", &fixture.state);
        assert_eq!(reset.err().as_deref(), Some("No recovery key is set up for this vault."));
    }

    #[test]
    fn v1_migration_unlocks_once_the_new_meta_is_in_place() {
        let fixture = ImportFixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        let salt = [7u8; 16];
        let master = derive_key("legacy password", &salt).unwrap();
        let mut meta = blank_meta();
        meta.salt = hex::encode(salt);
        meta.verifier = hex::encode(encrypt(&master, VERIFIER_PLAINTEXT).unwrap());
        write_meta(&dir, &meta).unwrap();
        persist_index(&vlock(&fixture.state), &master).unwrap();
        wipe_vault(&mut vlock(&fixture.state));
        let unlocked = with_failed_sync_after(&dir, "meta.json", || {
            unlock_with_password(&fixture.state, "legacy password")
        });
        unlocked.unwrap();
        assert_eq!(vlock(&fixture.state).key, Some(master));
        let migrated = read_meta(&dir).unwrap();
        assert!(migrated.wrapped_master.is_some());
        assert_eq!(master_from_password("legacy password", &migrated).unwrap(), master);
    }

    #[test]
    fn failed_vault_creation_leaves_no_vault_and_can_be_retried() {
        let fixture = ImportFixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        wipe_vault(&mut vlock(&fixture.state));

        // The index save fails and leaves its journal behind.
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(dir.clone()));
        let failed = create_new_vault(&fixture.state, "first password");
        FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert!(failed.is_err());
        assert!(dir.join("index.rollback").exists());
        assert!(!vlock(&fixture.state).has_meta());

        // The index lands under this attempt's master key, then meta fails.
        fs::create_dir(dir.join("meta.bak.tmp")).unwrap();
        assert!(create_new_vault(&fixture.state, "second password").is_err());
        fs::remove_dir(dir.join("meta.bak.tmp")).unwrap();
        assert!(dir.join("index.enc").exists());
        assert!(!vlock(&fixture.state).has_meta());
        assert!(vlock(&fixture.state).key.is_none());

        // A retry starts over with a new master key and its own index.
        create_new_vault(&fixture.state, "third password").unwrap();
        wipe_vault(&mut vlock(&fixture.state));
        assert!(unlock_with_password(&fixture.state, "second password").is_err());
        unlock_with_password(&fixture.state, "third password").unwrap();
    }

    #[test]
    fn vault_creation_counts_once_meta_is_in_place() {
        // meta.json lands but its sync fails.
        let fixture = ImportFixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        wipe_vault(&mut vlock(&fixture.state));
        with_failed_sync_after(&dir, "meta.json", || create_new_vault(&fixture.state, "password")).unwrap();
        assert!(vlock(&fixture.state).key.is_some());
        wipe_vault(&mut vlock(&fixture.state));
        unlock_with_password(&fixture.state, "password").unwrap();

        // Only meta.bak lands. Readers fall back to it, so the vault exists.
        let fixture = ImportFixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        wipe_vault(&mut vlock(&fixture.state));
        fs::create_dir(dir.join("meta.json.tmp")).unwrap();
        create_new_vault(&fixture.state, "password").unwrap();
        assert!(!dir.join("meta.json").exists());
        assert_eq!(
            create_new_vault(&fixture.state, "password").err().as_deref(),
            Some("Vault already exists.")
        );
        wipe_vault(&mut vlock(&fixture.state));
        unlock_with_password(&fixture.state, "password").unwrap();
    }

    #[test]
    fn lock_timer_reports_each_lock_the_ui_was_not_told_about() {
        let mut vault = test_vault(PathBuf::new(), Some(random_key()));
        vault.settings.auto_lock_secs = 60;
        let idle = |vault: &mut Vault| {
            vault.last_activity = Instant::now().checked_sub(Duration::from_secs(120)).unwrap();
        };
        assert!(!lock_tick(&mut vault, false));

        // A command or touch_activity finds the vault idle and wipes it
        // instead of reviving it. The next pass reports that once.
        idle(&mut vault);
        assert!(vault.active_key().is_none());
        assert!(lock_tick(&mut vault, false));
        assert!(!lock_tick(&mut vault, false));

        // The timer's own idle lock and a missed sleep are reported once too.
        vault.key = Some(random_key());
        idle(&mut vault);
        assert!(lock_tick(&mut vault, false));
        assert!(!lock_tick(&mut vault, false));
        vault.key = Some(random_key());
        vault.last_activity = Instant::now();
        assert!(lock_tick(&mut vault, true));
        assert!(!lock_tick(&mut vault, true));

        // A lock the UI already knows about isn't reported again.
        vault.key = Some(random_key());
        wipe_vault(&mut vault);
        vault.lock_unreported = false;
        assert!(!lock_tick(&mut vault, false));

        // An unlock before the next pass drops the stale report.
        vault.key = Some(random_key());
        wipe_vault(&mut vault);
        vault.key = Some(random_key());
        assert!(!lock_tick(&mut vault, false));
        wipe_vault(&mut vault);
        vault.lock_unreported = false;
        assert!(!lock_tick(&mut vault, false));
    }

    #[test]
    fn source_reads_stop_at_the_checked_size() {
        let data = read_capped(&mut &b"12345"[..], 5).unwrap();
        assert_eq!(data, b"12345");
        assert!(data.capacity() >= 5 + ENCRYPTION_OVERHEAD);
        // The file grew after its size was checked.
        let grown = read_capped(&mut &b"123456"[..], 5).unwrap_err();
        assert_eq!(grown.to_string(), "Source changed while it was being read.");
        let huge = read_capped(&mut &b""[..], isize::MAX as u64).unwrap_err();
        assert_eq!(huge.to_string(), "Not enough memory to import this file.");
    }

    #[test]
    fn failed_settings_save_keeps_the_old_file() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        save_settings(&vault).unwrap();
        let before = fs::read(vault.settings_path()).unwrap();
        vault.settings.auto_lock_secs = 5;
        fs::create_dir(vault.dir.join("settings.json.tmp")).unwrap();
        assert!(save_settings(&vault).is_err());
        assert_eq!(fs::read(vault.settings_path()).unwrap(), before);
    }

    #[test]
    fn settings_save_counts_once_the_new_file_is_in_place() {
        let fixture = ImportFixture::new();
        let mut vault = vlock(&fixture.state);
        save_settings(&vault).unwrap();
        vault.settings.auto_lock_secs = 0;
        // The rename lands but the directory sync fails. A restart reads the new
        // file, so callers must keep the new values instead of rolling back.
        FAIL_SYNC_AFTER_REPLACING.with(|path| *path.borrow_mut() = Some(vault.settings_path()));
        let saved = save_settings(&vault);
        FAIL_SYNC_AFTER_REPLACING.with(|path| path.borrow_mut().take());
        let failed_sync = FAIL_DIRECTORY_SYNC.with(|failure| failure.borrow_mut().take());
        assert_eq!(failed_sync.as_ref(), Some(&vault.dir));
        assert!(saved.is_ok());
        let on_disk: Settings = serde_json::from_slice(&fs::read(vault.settings_path()).unwrap()).unwrap();
        assert_eq!(on_disk.auto_lock_secs, 0);
    }
}
