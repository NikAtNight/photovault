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

use aes_gcm::aead::{Aead, KeyInit};
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
use zeroize::Zeroize;

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
    // Decrypted once at unlock and kept in memory; cleared on lock.
    photos: HashMap<String, PhotoInfo>,
    albums: HashMap<String, Album>,
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
    fn active_key(&mut self) -> Option<[u8; 32]> {
        if self.key.is_some()
            && self.settings.auto_lock_secs > 0
            && !self.importing
            && self.last_activity.elapsed().as_secs() > self.settings.auto_lock_secs
        {
            wipe_vault(self);
        }
        if self.key.is_some() {
            self.last_activity = Instant::now();
        }
        self.key
    }
}

/// Clear all secrets and decrypted state from memory.
fn wipe_vault(vault: &mut Vault) {
    if let Some(k) = vault.key.as_mut() {
        k.zeroize();
    }
    vault.key = None;
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
}

#[derive(Serialize)]
struct IndexOut<'a> {
    photos: &'a HashMap<String, PhotoInfo>,
    albums: &'a HashMap<String, Album>,
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

fn read_meta(dir: &std::path::Path) -> Result<Meta, String> {
    let primary = fs::read(dir.join("meta.json"))
        .and_then(|raw| serde_json::from_slice(&raw).map_err(std::io::Error::other));
    match primary {
        Ok(meta) => Ok(meta),
        Err(primary_err) => fs::read(dir.join("meta.bak"))
            .and_then(|raw| serde_json::from_slice(&raw).map_err(std::io::Error::other))
            .map_err(|backup_err| format!("{primary_err}; backup: {backup_err}")),
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_DIRECTORY_SYNC: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static AFTER_SOURCE_CLAIM: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
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

fn write_file_durably(
    tmp: &std::path::Path,
    dest: &std::path::Path,
    data: &[u8],
    dir: &std::path::Path,
) -> Result<(), String> {
    let mut file = fs::File::create(tmp).map_err(|e| e.to_string())?;
    file.write_all(data).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    fs::rename(tmp, dest).map_err(|e| e.to_string())?;
    sync_dir(dir)
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
fn write_meta(dir: &std::path::Path, meta: &Meta) -> Result<(), String> {
    let json = serde_json::to_vec(meta).map_err(|e| e.to_string())?;
    write_file_durably(
        &dir.join("meta.bak.tmp"),
        &dir.join("meta.bak"),
        &json,
        dir,
    )?;
    write_file_durably(
        &dir.join("meta.json.tmp"),
        &dir.join("meta.json"),
        &json,
        dir,
    )
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
        })
    }
}

fn load_index(vault: &Vault, key: &[u8; 32]) -> Result<IndexData, String> {
    let read = |path: PathBuf| -> Result<IndexData, String> {
        let blob = fs::read(path).map_err(|e| e.to_string())?;
        parse_index(&decrypt(key, &blob)?)
    };
    // Fall back to the previous generation if the current file is corrupt.
    read(vault.index_path()).or_else(|e| read(vault.index_bak_path()).map_err(|_| e))
}

/// Write the in-memory index back to disk, encrypted, keeping the previous
/// generation as index.bak.
fn persist_index(vault: &Vault, key: &[u8; 32]) -> Result<(), String> {
    let out = IndexOut {
        photos: &vault.photos,
        albums: &vault.albums,
    };
    let json = serde_json::to_vec(&out).map_err(|e| e.to_string())?;
    let blob = encrypt(key, &json)?;
    let tmp = vault.index_path().with_extension("tmp");
    let mut file = fs::File::create(&tmp).map_err(|e| e.to_string())?;
    file.write_all(&blob).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    let _ = fs::rename(vault.index_path(), vault.index_bak_path());
    fs::rename(tmp, vault.index_path()).map_err(|e| e.to_string())?;
    sync_dir(&vault.dir)
}

fn save_settings(vault: &Vault) -> Result<(), String> {
    fs::write(
        vault.settings_path(),
        serde_json::to_vec(&vault.settings).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

/// Load the index into memory and mark the vault unlocked. Also purges
/// photos that have been in the trash longer than the retention window.
fn finish_unlock(state: &Mutex<Vault>, master: [u8; 32]) -> Result<(), String> {
    let mut vault = vlock(state);
    let data = load_index(&vault, &master)?;
    vault.photos = data.photos;
    vault.albums = data.albums;
    let cutoff = now_secs() - TRASH_RETENTION_SECS;
    let expired: Vec<String> = vault
        .photos
        .iter()
        .filter(|(_, p)| p.deleted.map_or(false, |d| d < cutoff))
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
    for id in &expired {
        vault.photos.remove(id);
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
        persist_index(&vault, &master)?;
        for path in expired_blobs {
            let _ = fs::remove_file(path);
        }
    }
    vault.key = Some(master);
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
                return Err(ImportFailure {
                    reason: "File contents are not a supported image.".into(),
                    retryable: false,
                });
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
    Ok(if !vault.meta_path().exists() {
        "new".into()
    } else if vault.active_key().is_some() {
        "unlocked".into()
    } else {
        "locked".into()
    })
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
    {
        let vault = vlock(&state);
        if vault.meta_path().exists() {
            return Err("Vault already exists.".into());
        }
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
    rewrap_master(&mut meta, &password, &master)?; // slow (scrypt): outside the lock
    let mut vault = vlock(&state);
    fs::create_dir_all(vault.objects_dir()).map_err(|e| e.to_string())?;
    write_meta(&vault.dir, &meta)?;
    vault.photos = HashMap::new();
    vault.albums = HashMap::new();
    persist_index(&vault, &master)?;
    vault.key = Some(master);
    vault.last_activity = Instant::now();
    Ok(())
}

#[tauri::command]
async fn unlock(password: String, state: VaultState<'_>) -> Result<(), String> {
    let (dir, meta_mutex) = {
        let vault = vlock(&state);
        (vault.dir.clone(), vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    let meta = read_meta(&dir)?;
    let master = match master_from_password(&password, &meta) {
        Ok(m) => m,
        Err(e) => {
            std::thread::sleep(Duration::from_millis(500));
            return Err(e);
        }
    };
    // Seamless v1 → v2 migration: wrap the existing key as the master key.
    if meta.wrapped_master.is_none() {
        let mut meta = meta;
        rewrap_master(&mut meta, &password, &master)?;
        write_meta(&dir, &meta)?;
    }
    remove_legacy_meta_backup(&dir);
    finish_unlock(&state, master)
}

#[tauri::command]
async fn change_password(
    current_password: String,
    new_password: String,
    state: VaultState<'_>,
) -> Result<(), String> {
    if new_password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "New password must be at least {MIN_PASSWORD_LEN} characters."
        ));
    }
    let (dir, master, meta_mutex) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), key, vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    let mut meta = read_meta(&dir)?;
    master_from_password(&current_password, &meta)
        .map_err(|_| "Current password is incorrect.".to_string())?;
    rewrap_master(&mut meta, &new_password, &master)?;
    write_meta(&dir, &meta)?;
    remove_legacy_meta_backup(&dir);
    Ok(())
}

/// Generate (or replace) the recovery key. Returns it formatted for humans —
/// shown exactly once, never stored in plaintext.
#[tauri::command]
async fn recovery_generate(state: VaultState<'_>) -> Result<String, String> {
    let (dir, master, meta_mutex) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), key, vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    let rk = random_key();
    let mut meta = read_meta(&dir)?;
    meta.recovery = Some(hex::encode(encrypt(&rk, &master)?));
    write_meta(&dir, &meta)?;
    Ok(format_recovery_key(&rk))
}

#[tauri::command]
async fn recovery_disable(state: VaultState<'_>) -> Result<(), String> {
    let (dir, meta_mutex) = {
        let mut vault = vlock(&state);
        vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), vault.meta_lock.clone())
    };
    let _meta_guard = meta_lock(&meta_mutex);
    let mut meta = read_meta(&dir)?;
    meta.recovery = None;
    write_meta(&dir, &meta)?;
    remove_legacy_meta_backup(&dir);
    Ok(())
}

/// Forgot-password path: the recovery key unwraps the master key, and the
/// vault password is reset in the same step.
#[tauri::command]
async fn recovery_unlock(
    recovery_key: String,
    new_password: String,
    state: VaultState<'_>,
) -> Result<(), String> {
    if new_password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "New password must be at least {MIN_PASSWORD_LEN} characters."
        ));
    }
    let rk = parse_recovery_key(&recovery_key)?;
    let (dir, meta_mutex) = {
        let vault = vlock(&state);
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
    rewrap_master(&mut meta, &new_password, &master)?;
    write_meta(&dir, &meta)?;
    remove_legacy_meta_backup(&dir);
    finish_unlock(&state, master)
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
    vault.settings.touch_id = true;
    save_settings(&vault)
}

#[tauri::command]
async fn touchid_disable(state: VaultState<'_>) -> Result<(), String> {
    native::keychain_delete_master();
    let mut vault = vlock(&state);
    vault.settings.touch_id = false;
    save_settings(&vault)
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
#[tauri::command]
async fn touch_activity(state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    if vault.key.is_some() {
        vault.last_activity = Instant::now();
    }
    Ok(())
}

#[tauri::command]
async fn get_settings(state: VaultState<'_>) -> Result<Settings, String> {
    Ok(vlock(&state).settings.clone())
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
        vault.settings = Settings {
            touch_id,
            ..settings
        };
        vault.last_activity = Instant::now();
        save_settings(&vault)?;
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
        if vault.key.is_none() {
            continue;
        }
        let idle = vault.settings.auto_lock_secs > 0
            && !vault.importing
            && vault.last_activity.elapsed().as_secs() > vault.settings.auto_lock_secs;
        if idle || (slept && vault.settings.lock_on_sleep) {
            wipe_vault(&mut vault);
            drop(vault);
            let _ = app.emit("vault-locked", ());
        }
    }
}

#[tauri::command]
async fn lock(state: VaultState<'_>) -> Result<(), String> {
    wipe_vault(&mut vlock(&state));
    Ok(())
}

// --------------------------------------------------------- photo commands ---

#[tauri::command]
async fn list_photos(state: VaultState<'_>) -> Result<Vec<PhotoEntry>, String> {
    let mut vault = vlock(&state);
    vault.active_key().ok_or("locked")?;
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
    let mut vault = vlock(&state);
    vault.active_key().ok_or("locked")?;
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

#[tauri::command]
async fn album_create(name: String, state: VaultState<'_>) -> Result<String, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Album name can't be empty.".into());
    }
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    let id = random_id();
    vault.albums.insert(
        id.clone(),
        Album {
            name,
            created: now_secs(),
        },
    );
    persist_index(&vault, &key)?;
    Ok(id)
}

#[tauri::command]
async fn album_rename(id: String, name: String, state: VaultState<'_>) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Album name can't be empty.".into());
    }
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    vault.albums.get_mut(&id).ok_or("Album not found.")?.name = name;
    persist_index(&vault, &key)
}

#[tauri::command]
async fn album_delete(id: String, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    if vault.albums.remove(&id).is_some() {
        for p in vault.photos.values_mut() {
            p.albums.retain(|a| a != &id);
        }
        persist_index(&vault, &key)?;
    }
    Ok(())
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
    if !vault.albums.contains_key(&album) {
        return Err("Album not found.".into());
    }
    for id in &ids {
        if let Some(p) = vault.photos.get_mut(id) {
            if add && !p.albums.contains(&album) {
                p.albums.push(album.clone());
            } else if !add {
                p.albums.retain(|a| a != &album);
            }
        }
    }
    persist_index(&vault, &key)
}

#[tauri::command]
async fn set_favorite(
    ids: Vec<String>,
    favorite: bool,
    state: VaultState<'_>,
) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    for id in &ids {
        if let Some(p) = vault.photos.get_mut(id) {
            p.favorite = favorite;
        }
    }
    persist_index(&vault, &key)
}

#[tauri::command]
async fn rename_photo(id: String, name: String, state: VaultState<'_>) -> Result<(), String> {
    let name = sanitize_photo_name(&name)?;
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    vault.photos.get_mut(&id).ok_or("not found")?.name = name;
    persist_index(&vault, &key)
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
    vault.photos.get_mut(&id).ok_or("not found")?.tags = normalize_tags(tags);
    persist_index(&vault, &key)
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
        });
    }
}

#[derive(Debug)]
struct ImportFailure {
    reason: String,
    retryable: bool,
}

impl ImportFailure {
    fn temporary(reason: impl ToString) -> Self {
        Self {
            reason: reason.to_string(),
            retryable: true,
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

fn read_source(path: &std::path::Path) -> Result<(Vec<u8>, SourceProof), ImportFailure> {
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
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(ImportFailure::temporary)?;
    if file_signature(&metadata)
        != file_signature(&file.metadata().map_err(ImportFailure::temporary)?)
    {
        return Err(ImportFailure::temporary(
            "Source changed while it was being read.",
        ));
    }
    let hash = blake3::hash(&data);
    Ok((data, SourceProof { metadata, hash }))
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
    let mut vault = vlock(state);
    vault.active_key().ok_or("locked")?;
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
    // Re-check the key: the vault may have been locked mid-import.
    let key = vault.key.ok_or("locked")?;
    vault.last_activity = Instant::now(); // a running import counts as activity
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

/// Rename first so replacing the original pathname cannot make cleanup delete the replacement.
/// A crash or changed source leaves the claimed file in a visible, automatically scanned folder.
fn delete_inbox_source(
    inbox: &std::path::Path,
    path: &std::path::Path,
    proof: &SourceProof,
    retained: &mut Option<PathBuf>,
) -> Result<(), String> {
    let parent = path.parent().ok_or("Source has no parent directory.")?;
    let claimed_dir = inbox.join(format!("Pending import {}", random_id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&claimed_dir)
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&claimed_dir).map_err(|e| e.to_string())?;
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
        let (_, current) = read_source(&claimed).map_err(|e| e.reason)?;
        if !same_source(&proof.metadata, &current.metadata) || proof.hash != current.hash {
            return Err("Source changed after it was read; the changed file was preserved.".into());
        }
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
    match read_source(path) {
        Ok((_, current))
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
    let (Ok(enc), Ok(enc_thumb)) = (encrypt(key, &data), encrypt(key, &media.thumb)) else {
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
            size: Some(data.len() as u64),
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
    if vault.importing {
        return Ok(0); // objects being written right now — don't touch anything
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
    Ok(removed)
}

// ------------------------------------------------------------------ trash ---

#[tauri::command]
async fn trash_photos(ids: Vec<String>, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    if vault.importing {
        return Err("An import is running — wait for it to finish.".into());
    }
    let now = now_secs();
    for id in &ids {
        if let Some(p) = vault.photos.get_mut(id) {
            p.deleted = Some(now);
        }
    }
    persist_index(&vault, &key)
}

#[tauri::command]
async fn restore_photos(ids: Vec<String>, state: VaultState<'_>) -> Result<(), String> {
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    for id in &ids {
        if let Some(p) = vault.photos.get_mut(id) {
            p.deleted = None;
        }
    }
    persist_index(&vault, &key)
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
    let count = vault.photos.len();
    vault.photos.clear();
    vault.albums.clear();
    vault.media_cache = None;
    vault.thumb_cache.clear();
    vault.thumb_order.clear();
    persist_index(&vault, &key)?;
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
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match safe_name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (safe_name.to_string(), String::new()),
    };
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
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
    let data = decrypt(&key, &blob)?;
    fs::write(dest, data).map_err(|e| e.to_string())
}

/// Export selected photos (`ids`) or the whole non-trashed library (None).
#[tauri::command]
async fn export_photos(
    dest: String,
    ids: Option<Vec<String>>,
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<usize, String> {
    let (key, objects, entries) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        let entries: Vec<(String, String)> = match &ids {
            Some(ids) => ids
                .iter()
                .filter_map(|id| vault.photos.get(id).map(|p| (id.clone(), p.name.clone())))
                .collect(),
            None => vault
                .photos
                .iter()
                .filter(|(_, p)| p.deleted.is_none())
                .map(|(id, info)| (id.clone(), info.name.clone()))
                .collect(),
        };
        (key, vault.objects_dir(), entries)
    };
    let dir = PathBuf::from(&dest);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let total = entries.len();
    let mut count = 0usize;
    for (i, (id, name)) in entries.iter().enumerate() {
        if i % 25 == 0 {
            let _ = app.emit("export-progress", ImportProgress { done: i, total });
        }
        let Ok(blob) = fs::read(objects.join(id)) else {
            continue;
        };
        let Ok(data) = decrypt(&key, &blob) else {
            continue;
        };
        if fs::write(unique_dest(&dir, name), data).is_ok() {
            count += 1;
        }
    }
    let _ = app.emit("export-progress", ImportProgress { done: total, total });
    Ok(count)
}

/// Zip the whole vault directory (everything already encrypted) — a portable,
/// cloud-safe backup. Restore = unzip over the vault folder while the app is
/// closed.
#[tauri::command]
async fn backup_vault(
    dest: String,
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<usize, String> {
    use std::io::Write;
    let dir = {
        let mut vault = vlock(&state);
        vault.active_key().ok_or("locked")?;
        vault.dir.clone()
    };
    let file = fs::File::create(&dest).map_err(|e| e.to_string())?;
    let mut zw = zip::ZipWriter::new(file);
    // Stored, not deflated: the payload is AES-GCM output, incompressible.
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true);
    let mut count = 0usize;
    for name in [
        "meta.json",
        "meta.bak",
        "settings.json",
        "index.enc",
        "index.bak",
    ] {
        if let Ok(bytes) = fs::read(dir.join(name)) {
            zw.start_file(name, opts).map_err(|e| e.to_string())?;
            zw.write_all(&bytes).map_err(|e| e.to_string())?;
            count += 1;
        }
    }
    let objects: Vec<PathBuf> = fs::read_dir(dir.join("objects"))
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .collect();
    let total = objects.len();
    for (i, p) in objects.iter().enumerate() {
        if i % 50 == 0 {
            let _ = app.emit("backup-progress", ImportProgress { done: i, total });
        }
        let Some(fname) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        zw.start_file(format!("objects/{fname}"), opts)
            .map_err(|e| e.to_string())?;
        let mut f = fs::File::open(p).map_err(|e| e.to_string())?;
        std::io::copy(&mut f, &mut zw).map_err(|e| e.to_string())?;
        count += 1;
    }
    zw.finish().map_err(|e| e.to_string())?;
    let _ = app.emit("backup-progress", ImportProgress { done: total, total });
    Ok(count)
}

/// A backup zip entry we're willing to extract: one of the known top-level
/// files, or objects/<id>[.t] — no absolute paths, no traversal, no nesting.
fn safe_backup_entry(name: &str) -> bool {
    if name.contains("..") || name.starts_with('/') || name.contains('\\') {
        return false;
    }
    matches!(
        name,
        "meta.json" | "meta.bak" | "settings.json" | "index.enc" | "index.bak"
    ) || name == "objects/"
        || name
            .strip_prefix("objects/")
            .map_or(false, |f| !f.is_empty() && !f.contains('/'))
}

/// Restore a vault from a backup zip (created by backup_vault). Only allowed
/// while locked; the existing vault directory is moved aside, never deleted.
#[tauri::command]
async fn restore_backup(src: String, state: VaultState<'_>) -> Result<(), String> {
    let dir = {
        let mut vault = vlock(&state);
        if vault.active_key().is_some() {
            return Err("Lock the vault before restoring a backup.".into());
        }
        vault.dir.clone()
    };
    let file = fs::File::open(&src).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|_| "That file isn't a readable zip archive.".to_string())?;
    let mut has_meta = false;
    for i in 0..zip.len() {
        let name = zip
            .by_index(i)
            .map_err(|e| e.to_string())?
            .name()
            .to_string();
        if !safe_backup_entry(&name) {
            return Err("The backup contains unexpected files — not restoring.".into());
        }
        has_meta |= name == "meta.json";
    }
    if !has_meta {
        return Err("That zip doesn't look like a PhotoVault backup (no meta.json).".into());
    }
    // Keep the current vault as a sibling directory rather than deleting it.
    if dir.join("meta.json").exists() {
        let aside = dir.with_file_name(format!("vault.pre-restore-{}", now_secs() as u64));
        fs::rename(&dir, &aside).map_err(|e| e.to_string())?;
    }
    fs::create_dir_all(dir.join("objects")).map_err(|e| e.to_string())?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let mut out = fs::File::create(dir.join(&name)).map_err(|e| e.to_string())?;
        std::io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
    }
    // Adopt the restored settings (auto-lock, dedupe, …) immediately.
    let mut vault = vlock(&state);
    if let Some(s) = fs::read(vault.settings_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<Settings>(&b).ok())
    {
        vault.settings = s;
    }
    Ok(())
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
        let Ok(data) = decrypt(&key, &blob) else {
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
    for (id, t) in updates {
        if let Some(p) = vault.photos.get_mut(&id) {
            p.taken = Some(t);
        }
    }
    if n > 0 {
        persist_index(&vault, &key)?;
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
        let Some(key) = vault.active_key() else {
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
            let Ok(plain) = decrypt(&key, &blob) else {
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

/// Media files anywhere under the inbox — folders dropped in are walked
/// recursively, and the result is sorted by name so files are imported in the
/// order the inbox folder shows them. Hidden entries and symlinks are skipped;
/// depth is bounded so a pathological tree can't wedge the watcher.
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
        } else if ft.is_file() && is_media_path(&path) {
            if let Ok(md) = entry.metadata() {
                out.push((path, file_signature(&md)));
            }
        }
    }
    if depth == 0 {
        out.sort_by_cached_key(|(path, _)| path_sort_key(path));
    }
}

/// After importing a folder's media, remove the folders it leaves empty,
/// walking up to (but never into or past) the inbox root. `remove_dir` only
/// deletes empty directories, so anything still holding files survives —
/// except a lone Finder .DS_Store, which shouldn't keep a folder alive.
fn prune_empty_dirs(inbox: &std::path::Path, from: &std::path::Path) {
    let mut dir = from.to_path_buf();
    while dir != *inbox && dir.starts_with(inbox) {
        let ds = dir.join(".DS_Store");
        let only_ds = ds.exists()
            && fs::read_dir(&dir).map_or(false, |mut entries| {
                entries.all(|e| e.map_or(false, |e| e.file_name() == ".DS_Store"))
            });
        if only_ds {
            let _ = fs::remove_file(&ds);
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

/// Import inbox files and remove only plaintext originals whose encrypted
/// object and index entry are safely persisted. Failed/undecodable files stay
/// in the inbox so the user can inspect or replace them.
fn run_inbox_import(
    files: Vec<PathBuf>,
    key: [u8; 32],
    objects: PathBuf,
    mut hashes: HashMap<String, String>,
    skip_dups: bool,
    inbox: &std::path::Path,
    mut progress: impl FnMut(ImportProgress),
    state: &Mutex<Vault>,
) -> ImportResult {
    let total = files.len();
    let mut batch = Vec::new();
    let mut pending = Vec::new();
    let mut result = ImportResult::default();
    for (i, path) in files.iter().enumerate() {
        if i % 25 == 0 {
            progress(ImportProgress { done: i, total });
        }
        let mut outcome = import_one(&key, &objects, path, &mut hashes, skip_dups);
        if let ImportOutcome::Skipped(existing, _) = &outcome {
            if batch.iter().any(|(id, _)| id == existing)
                && !commit_inbox_batch(state, &mut batch, &mut pending, inbox, &mut result)
            {
                for path in &files[i..] {
                    result.issue(
                        path,
                        "Not imported because the index could not be saved.".into(),
                        "import",
                        true,
                    );
                }
                return result;
            }
            if !skipped_target_is_live(state, existing) {
                outcome = import_one(&key, &objects, path, &mut hashes, false);
            }
        }
        match outcome {
            ImportOutcome::Added(id, info, proof) => {
                pending.push((path.clone(), id.clone(), proof));
                batch.push((id, info));
                if batch.len() >= 20
                    && !commit_inbox_batch(state, &mut batch, &mut pending, inbox, &mut result)
                {
                    for path in &files[i + 1..] {
                        result.issue(
                            path,
                            "Not attempted because the index could not be saved.".into(),
                            "import",
                            true,
                        );
                    }
                    return result;
                }
            }
            ImportOutcome::Skipped(id, proof) => {
                result.skipped += 1;
                cleanup_inbox_source(state, inbox, path, &id, &proof, &mut result);
            }
            ImportOutcome::Failed(e) => result.issue(path, e.reason, "import", e.retryable),
        }
    }
    commit_inbox_batch(state, &mut batch, &mut pending, inbox, &mut result);
    progress(ImportProgress { done: total, total });
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
        if blake3::hash(&decrypt(&key, &encrypted)?) != proof.hash {
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
) -> bool {
    if let Err(e) = flush_batch(state, batch) {
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
        |progress| {
            let _ = app.emit("import-progress", progress);
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
    fn record(signature: FileSig, previous: Option<&Self>, retryable: bool, now: Instant) -> Self {
        let attempts = previous
            .filter(|p| p.signature == signature)
            .map_or(1, |p| p.attempts.saturating_add(1));
        let delay = 2u64.saturating_pow(attempts.min(6)).min(60);
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
    let retry = InboxRetry::record(retry_sig, previous.as_ref(), issue.retryable, now);
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
        let _import_guard = match claim_import(&*state) {
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
            |_| {},
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
            let dir = app.path().app_data_dir()?.join("vault");
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
                photos: HashMap::new(),
                albums: HashMap::new(),
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
            lock_screen_info,
            create_vault,
            unlock,
            lock,
            touch_activity,
            change_password,
            recovery_generate,
            recovery_disable,
            recovery_unlock,
            touchid_available,
            touchid_enable,
            touchid_disable,
            touchid_unlock,
            get_settings,
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

    fn test_vault(dir: PathBuf, key: Option<[u8; 32]>) -> Vault {
        Vault {
            dir,
            inbox: PathBuf::new(),
            key,
            photos: HashMap::new(),
            albums: HashMap::new(),
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
        assert!(!commit_inbox_batch(&state, &mut batch, &mut pending, &inbox, &mut result));
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
            photos: HashMap::new(),
            albums: HashMap::new(),
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

        fn run(&self, files: Vec<PathBuf>, progress: impl FnMut(ImportProgress)) -> ImportResult {
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
                progress,
                &self.state,
            )
        }
    }

    impl Drop for ImportFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
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
        let retry = InboxRetry::record(found[0].1, None, true, now);
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
        let result = fixture.run(files.clone(), |progress| {
            if progress.done == 25 {
                fs::create_dir(&index_tmp).unwrap();
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
        let mut retry = InboxRetry::record(sig, None, true, now);
        assert!(!retry.ready(sig, now));
        assert!(retry.ready(sig, now + Duration::from_secs(2)));
        for _ in 0..100 {
            retry = InboxRetry::record(sig, Some(&retry), true, now);
        }
        assert!(retry.ready(sig, now + Duration::from_secs(60)));
        let permanent = InboxRetry::record(sig, None, false, now);
        assert!(!permanent.ready(sig, now + Duration::from_secs(86400)));
        fs::remove_file(&path).unwrap();
        fixture.photo("source.png", 2);
        let replaced = file_signature(&fs::metadata(path).unwrap());
        assert!(permanent.ready(replaced, now));
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
}
