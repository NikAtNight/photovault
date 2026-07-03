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
use std::collections::{HashMap, HashSet};
use std::fs;
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
    // Last decrypted full object, so video seeking doesn't re-decrypt the
    // whole file per range request. Cleared on lock.
    media_cache: Option<(String, Arc<Vec<u8>>)>,
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
    if let Some(mut k) = vault.key.take() {
        k.zeroize();
    }
    vault.photos.clear();
    vault.albums.clear();
    vault.media_cache = None;
}

type VaultState<'a> = State<'a, Mutex<Vault>>;

/// Lock the vault mutex, recovering from poisoning (a panicked thread must
/// not brick the whole app — Vault state stays consistent either way).
fn vlock(m: &Mutex<Vault>) -> MutexGuard<'_, Vault> {
    m.lock().unwrap_or_else(|e| e.into_inner())
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
    // encrypt(kek, master). Absent = v1 layout (master derived directly
    // from the password); migrated in place on first unlock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped_master: Option<String>,
    // encrypt(recovery_key_bytes, master)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<String>,
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

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = scrypt::Params::new(15, 8, 1, 32).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
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
    let raw = fs::read(dir.join("meta.json")).map_err(|e| e.to_string())?;
    serde_json::from_slice(&raw).map_err(|e| e.to_string())
}

fn write_meta(dir: &std::path::Path, meta: &Meta) -> Result<(), String> {
    let json = serde_json::to_vec(meta).map_err(|e| e.to_string())?;
    let tmp = dir.join("meta.json.tmp");
    fs::write(&tmp, json).map_err(|e| e.to_string())?;
    fs::rename(tmp, dir.join("meta.json")).map_err(|e| e.to_string())
}

/// Unwrap the master key with a password against the given meta.
/// Handles both the v2 envelope layout and the v1 direct-derivation layout.
fn master_from_password(password: &str, meta: &Meta) -> Result<[u8; 32], String> {
    let salt = hex::decode(&meta.salt).map_err(|e| e.to_string())?;
    let derived = derive_key(password, &salt)?;
    let master = match &meta.wrapped_master {
        Some(wm) => {
            let blob = hex::decode(wm).map_err(|e| e.to_string())?;
            key_from_slice(&decrypt(&derived, &blob).map_err(|_| "Wrong password.".to_string())?)?
        }
        None => derived, // v1: the derived key IS the master key
    };
    let verifier = hex::decode(&meta.verifier).map_err(|e| e.to_string())?;
    match decrypt(&master, &verifier) {
        Ok(pt) if pt == VERIFIER_PLAINTEXT => Ok(master),
        _ => Err("Wrong password.".into()),
    }
}

/// Re-wrap the master key under a (new) password. Used by vault creation,
/// v1→v2 migration, password change, and recovery reset.
fn rewrap_master(meta: &mut Meta, password: &str, master: &[u8; 32]) -> Result<(), String> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = derive_key(password, &salt)?;
    meta.salt = hex::encode(salt);
    meta.wrapped_master = Some(hex::encode(encrypt(&kek, master)?));
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
    fs::write(&tmp, blob).map_err(|e| e.to_string())?;
    let _ = fs::rename(vault.index_path(), vault.index_bak_path());
    fs::rename(tmp, vault.index_path()).map_err(|e| e.to_string())
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
    for id in &expired {
        let _ = fs::remove_file(vault.objects_dir().join(id));
        let _ = fs::remove_file(vault.objects_dir().join(format!("{id}.t")));
        vault.photos.remove(id);
    }
    if !expired.is_empty() {
        let _ = persist_index(&vault, &master);
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

/// Convert an image the decoder can't read (HEIC from iPhones) to JPEG using
/// macOS's built-in `sips`. The source is already plaintext on disk, so the
/// short-lived plaintext conversion in the private temp dir doesn't weaken
/// the at-rest story.
fn sips_to_jpeg(src: &std::path::Path) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("pv-conv-{}", random_id()));
    fs::create_dir_all(&dir).ok()?;
    let out = dir.join("converted.jpg");
    let status = std::process::Command::new("/usr/bin/sips")
        .args(["-s", "format", "jpeg"])
        .arg(src)
        .arg("--out")
        .arg(&out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let bytes = match status {
        Ok(s) if s.success() => fs::read(&out).ok(),
        _ => None,
    };
    let _ = fs::remove_dir_all(&dir);
    bytes
}

/// Poster frame for a video via QuickLook's thumbnailer.
fn video_thumbnail(src: &std::path::Path) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("pv-thumb-{}", random_id()));
    fs::create_dir_all(&dir).ok()?;
    let status = std::process::Command::new("/usr/bin/qlmanage")
        .args(["-t", "-s", "960", "-o"])
        .arg(&dir)
        .arg(src)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let mut png = None;
    if matches!(status, Ok(s) if s.success()) {
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
/// dimensions along the way. Returns None only for undecodable images.
fn prepare_media(path: &std::path::Path, data: &[u8]) -> Option<MediaMeta> {
    if is_media_path(path) && is_video_name(&path.file_name()?.to_string_lossy()) {
        let thumb = video_thumbnail(path).unwrap_or_else(placeholder_thumb);
        let taken = fs::metadata(path)
            .ok()
            .and_then(|m| m.created().or_else(|_| m.modified()).ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64());
        return Some(MediaMeta {
            thumb,
            width: None,
            height: None,
            taken,
        });
    }
    let (img, converted) = match image::load_from_memory(data) {
        Ok(img) => (img, None),
        Err(_) => {
            let jpg = sips_to_jpeg(path)?;
            let img = image::load_from_memory(&jpg).ok()?;
            (img, Some(jpg))
        }
    };
    let orient_src: &[u8] = converted.as_deref().unwrap_or(data);
    let img = apply_orientation(img, exif_orientation(orient_src));
    let (width, height) = (img.width(), img.height());
    let thumb = encode_thumb(&img)?;
    let taken = exif_taken(data).or_else(|| converted.as_deref().and_then(exif_taken));
    Some(MediaMeta {
        thumb,
        width: Some(width),
        height: Some(height),
        taken,
    })
}

/// Expand files and folders into a flat list of media-file paths.
/// Folders are walked recursively; hidden entries are skipped.
fn collect_files(paths: &[String]) -> Vec<PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_hidden(&path) {
                continue;
            }
            if path.is_dir() {
                walk(&path, out);
            } else if is_media_path(&path) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    for p in paths {
        let path = PathBuf::from(p);
        if path.is_dir() {
            walk(&path, &mut out);
        } else {
            out.push(path); // direct files: let the decoder decide
        }
    }
    // The same path can appear twice (e.g. a file selected alongside its
    // parent folder) — import each actual file once per import action.
    let mut unique = HashSet::new();
    out.retain(|p| unique.insert(p.clone()));
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
    let has_recovery = read_meta(&dir).map(|m| m.recovery.is_some()).unwrap_or(false);
    let inbox_pending = fs::read_dir(&inbox)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    let p = e.path();
                    !is_hidden(&p) && p.is_file() && is_media_path(&p)
                })
                .count()
        })
        .unwrap_or(0);
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
    let dir = vlock(&state).dir.clone();
    let meta = read_meta(&dir)?;
    let master = match master_from_password(&password, &meta) {
        Ok(m) => m,
        Err(e) => {
            std::thread::sleep(Duration::from_millis(500));
            return Err(e);
        }
    };
    // Seamless v1 → v2 migration: wrap the existing key as the master key.
    // The original meta is kept once as meta.v1.bak, so an older build of the
    // app can still open the vault if needed.
    if meta.wrapped_master.is_none() {
        let bak = dir.join("meta.v1.bak");
        if !bak.exists() {
            let _ = fs::copy(dir.join("meta.json"), bak);
        }
        let mut meta = meta;
        rewrap_master(&mut meta, &password, &master)?;
        write_meta(&dir, &meta)?;
    }
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
    let (dir, master) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), key)
    };
    let mut meta = read_meta(&dir)?;
    master_from_password(&current_password, &meta)
        .map_err(|_| "Current password is incorrect.".to_string())?;
    rewrap_master(&mut meta, &new_password, &master)?;
    write_meta(&dir, &meta)
}

/// Generate (or replace) the recovery key. Returns it formatted for humans —
/// shown exactly once, never stored in plaintext.
#[tauri::command]
async fn recovery_generate(state: VaultState<'_>) -> Result<String, String> {
    let (dir, master) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        (vault.dir.clone(), key)
    };
    let rk = random_key();
    let mut meta = read_meta(&dir)?;
    meta.recovery = Some(hex::encode(encrypt(&rk, &master)?));
    write_meta(&dir, &meta)?;
    Ok(format_recovery_key(&rk))
}

#[tauri::command]
async fn recovery_disable(state: VaultState<'_>) -> Result<(), String> {
    let dir = {
        let mut vault = vlock(&state);
        vault.active_key().ok_or("locked")?;
        vault.dir.clone()
    };
    let mut meta = read_meta(&dir)?;
    meta.recovery = None;
    write_meta(&dir, &meta)
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
    let dir = vlock(&state).dir.clone();
    let mut meta = read_meta(&dir)?;
    let wrapped = meta
        .recovery
        .clone()
        .ok_or("No recovery key is set up for this vault.")?;
    let blob = hex::decode(&wrapped).map_err(|e| e.to_string())?;
    let master = match decrypt(&rk, &blob).and_then(|m| key_from_slice(&m)) {
        Ok(m) => m,
        Err(_) => {
            std::thread::sleep(Duration::from_millis(500));
            return Err("Wrong recovery key.".into());
        }
    };
    let verifier = hex::decode(&meta.verifier).map_err(|e| e.to_string())?;
    match decrypt(&master, &verifier) {
        Ok(pt) if pt == VERIFIER_PLAINTEXT => {}
        _ => return Err("Wrong recovery key.".into()),
    }
    rewrap_master(&mut meta, &new_password, &master)?;
    write_meta(&dir, &meta)?;
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
        _ => Err("The stored Touch ID key no longer matches this vault — re-enable it in Settings.".into()),
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
        if vault.key.is_none() || vault.importing {
            continue; // never yank the key mid-import
        }
        let idle = vault.settings.auto_lock_secs > 0
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
    vault
        .albums
        .get_mut(&id)
        .ok_or("Album not found.")?
        .name = name;
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
async fn set_favorite(ids: Vec<String>, favorite: bool, state: VaultState<'_>) -> Result<(), String> {
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
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name can't be empty.".into());
    }
    let mut vault = vlock(&state);
    let key = vault.active_key().ok_or("locked")?;
    vault.photos.get_mut(&id).ok_or("not found")?.name = name;
    persist_index(&vault, &key)
}

// ----------------------------------------------------------------- import ---

#[derive(Serialize, Clone)]
struct ImportProgress {
    done: usize,
    total: usize,
}

#[derive(Serialize)]
struct ImportResult {
    imported: usize,
    skipped: usize,
}

enum ImportOutcome {
    Added(String, PhotoInfo),
    Skipped,
    Failed,
}

/// Merge a batch of imported photos into the index and persist it.
fn flush_batch(state: &VaultState<'_>, batch: &mut Vec<(String, PhotoInfo)>) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut vault = vlock(state);
    // Re-check the key: the vault may have been locked mid-import.
    let key = vault.key.ok_or("locked")?;
    vault.last_activity = Instant::now(); // a running import counts as activity
    for (id, info) in batch.drain(..) {
        vault.photos.insert(id, info);
    }
    persist_index(&vault, &key)
}

/// Encrypt one file into the vault objects dir. `hashes` carries the content
/// hashes already in the vault (and this batch) for duplicate skipping.
fn import_one(
    key: &[u8; 32],
    objects: &std::path::Path,
    path: &std::path::Path,
    hashes: &mut HashSet<String>,
    skip_dups: bool,
) -> ImportOutcome {
    let Ok(data) = fs::read(path) else {
        return ImportOutcome::Failed;
    };
    let hash = blake3::hash(&data).to_hex().to_string();
    if skip_dups && hashes.contains(&hash) {
        return ImportOutcome::Skipped;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "photo".into());
    let Some(media) = prepare_media(path, &data) else {
        return ImportOutcome::Failed;
    };
    let (Ok(enc), Ok(enc_thumb)) = (encrypt(key, &data), encrypt(key, &media.thumb)) else {
        return ImportOutcome::Failed;
    };
    let id = random_id();
    if fs::write(objects.join(&id), enc).is_err()
        || fs::write(objects.join(format!("{id}.t")), enc_thumb).is_err()
    {
        let _ = fs::remove_file(objects.join(&id));
        return ImportOutcome::Failed;
    }
    hashes.insert(hash.clone());
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
            width: media.width,
            height: media.height,
        },
    )
}

/// Content hashes eligible for duplicate skipping. Trashed photos don't
/// count — they're on a purge timer, so a re-import must create a fresh copy
/// rather than being "skipped" into eventual data loss.
fn existing_hashes(vault: &Vault) -> HashSet<String> {
    vault
        .photos
        .values()
        .filter(|p| p.deleted.is_none())
        .filter_map(|p| p.hash.clone())
        .collect()
}

fn run_import(
    files: Vec<PathBuf>,
    key: [u8; 32],
    objects: PathBuf,
    mut hashes: HashSet<String>,
    skip_dups: bool,
    app: &tauri::AppHandle,
    state: &VaultState<'_>,
) -> Result<ImportResult, String> {
    let total = files.len();
    let mut batch: Vec<(String, PhotoInfo)> = Vec::new();
    let mut imported = 0usize;
    let mut skipped = 0usize;
    for (i, path) in files.iter().enumerate() {
        if i % 25 == 0 {
            let _ = app.emit("import-progress", ImportProgress { done: i, total });
        }
        match import_one(&key, &objects, path, &mut hashes, skip_dups) {
            ImportOutcome::Added(id, info) => {
                batch.push((id, info));
                imported += 1;
                // Persist periodically so a crash mid-import keeps what's done.
                if batch.len() >= 100 {
                    flush_batch(state, &mut batch)?;
                }
            }
            ImportOutcome::Skipped => skipped += 1,
            ImportOutcome::Failed => {}
        }
    }
    flush_batch(state, &mut batch)?;
    let _ = app.emit("import-progress", ImportProgress { done: total, total });
    Ok(ImportResult { imported, skipped })
}

#[tauri::command]
async fn import_photos(
    paths: Vec<String>,
    app: tauri::AppHandle,
    state: VaultState<'_>,
) -> Result<ImportResult, String> {
    let (key, objects, hashes, skip_dups) = {
        let mut vault = vlock(&state);
        let key = vault.active_key().ok_or("locked")?;
        if vault.importing {
            return Err("An import is already running.".into());
        }
        vault.importing = true;
        (
            key,
            vault.objects_dir(),
            existing_hashes(&vault),
            vault.settings.skip_duplicates,
        )
    };
    // Heavy work (decode + encrypt) happens outside the mutex.
    let result = run_import(
        collect_files(&paths),
        key,
        objects,
        hashes,
        skip_dups,
        &app,
        &state,
    );
    vlock(&state).importing = false;
    result
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
    let mut changed = false;
    for id in &ids {
        if vault.photos.remove(id).is_some() {
            changed = true;
            let _ = fs::remove_file(vault.objects_dir().join(id));
            let _ = fs::remove_file(vault.objects_dir().join(format!("{id}.t")));
        }
    }
    if changed {
        if let Some((cid, _)) = &vault.media_cache {
            if ids.contains(cid) {
                vault.media_cache = None;
            }
        }
        persist_index(&vault, &key)?;
    }
    Ok(())
}

#[tauri::command]
async fn empty_trash(state: VaultState<'_>) -> Result<usize, String> {
    let ids: Vec<String> = {
        let mut vault = vlock(&state);
        vault.active_key().ok_or("locked")?;
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
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (name.to_string(), String::new()),
    };
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
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
    for name in ["meta.json", "settings.json", "index.enc", "index.bak"] {
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
        .header("Access-Control-Allow-Origin", "*");
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

fn media_error(status: u16) -> tauri::http::Response<Vec<u8>> {
    tauri::http::Response::builder()
        .status(status)
        .header("Access-Control-Allow-Origin", "*")
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
        let cached = (!thumb)
            .then(|| {
                vault
                    .media_cache
                    .as_ref()
                    .filter(|(cid, _)| cid == id)
                    .map(|(_, d)| d.clone())
            })
            .flatten();
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
            if !thumb && is_video_name(&name) {
                let mut vault = vlock(&state);
                if vault.key.is_some() {
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

#[derive(Serialize, Clone)]
struct InboxImported {
    count: usize,
}

/// Watch the inbox folder: media saved there is encrypted into the vault and
/// the plaintext originals removed. A file is only picked up once its
/// size/mtime is unchanged across two scans (i.e. the download finished),
/// and only while the vault is unlocked.
fn inbox_watcher(app: tauri::AppHandle) {
    let mut prev: HashMap<PathBuf, (u64, SystemTime)> = HashMap::new();
    let mut failed: HashSet<PathBuf> = HashSet::new();
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let state: State<Mutex<Vault>> = app.state();
        let inbox = vlock(&state).inbox.clone();
        let mut ready: Vec<PathBuf> = Vec::new();
        let mut cur: HashMap<PathBuf, (u64, SystemTime)> = HashMap::new();
        let Ok(entries) = fs::read_dir(&inbox) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_hidden(&path) || !path.is_file() || !is_media_path(&path) || failed.contains(&path)
            {
                continue;
            }
            let Ok(md) = entry.metadata() else { continue };
            let sig = (md.len(), md.modified().unwrap_or(UNIX_EPOCH));
            if prev.get(&path) == Some(&sig) {
                ready.push(path.clone());
            }
            cur.insert(path, sig);
        }
        prev = cur;
        if ready.is_empty() {
            continue;
        }
        let (key, objects, mut hashes, skip_dups) = {
            let mut vault = vlock(&state);
            let Some(key) = vault.active_key() else { continue };
            if vault.importing {
                continue;
            }
            vault.importing = true;
            (
                key,
                vault.objects_dir(),
                existing_hashes(&vault),
                vault.settings.skip_duplicates,
            )
        };
        let mut batch: Vec<(String, PhotoInfo)> = Vec::new();
        let mut imported = 0usize;
        for path in &ready {
            match import_one(&key, &objects, path, &mut hashes, skip_dups) {
                ImportOutcome::Added(id, info) => {
                    batch.push((id, info));
                    imported += 1;
                    let _ = fs::remove_file(path);
                }
                // An identical copy is already in the vault — the plaintext
                // can go.
                ImportOutcome::Skipped => {
                    let _ = fs::remove_file(path);
                }
                // Unreadable/undecodable: leave the file, stop retrying it.
                ImportOutcome::Failed => {
                    failed.insert(path.clone());
                }
            }
        }
        let flush = flush_batch(&state, &mut batch);
        vlock(&state).importing = false;
        if flush.is_ok() && imported > 0 {
            let _ = app.emit("inbox-imported", InboxImported { count: imported });
        }
    }
}

// ------------------------------------------------------------------ main ---

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .register_asynchronous_uri_scheme_protocol("pvmedia", |ctx, request, responder| {
            let app = ctx.app_handle().clone();
            // Decrypt off the protocol thread so many concurrent thumbnail
            // loads never queue behind each other.
            std::thread::spawn(move || {
                responder.respond(serve_media(&app, &request));
            });
        })
        .setup(|app| {
            let dir = app.path().app_data_dir()?.join("vault");
            fs::create_dir_all(&dir)?;
            let inbox = app.path().home_dir()?.join("PhotoVault Inbox");
            fs::create_dir_all(&inbox)?;
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
                media_cache: None,
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
                    vault.settings.lock_on_sleep && vault.key.is_some() && !vault.importing
                };
                if should {
                    do_system_lock(&handle);
                }
            });
            let handle = app.handle().clone();
            std::thread::spawn(move || inbox_watcher(handle));
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
            rename_photo,
            import_photos,
            cleanup_orphans,
            trash_photos,
            restore_photos,
            purge_photos,
            empty_trash,
            clear_vault,
            export_photo,
            export_photos,
            backup_vault,
            scan_dates
        ])
        .run(tauri::generate_context!())
        .expect("error while running PhotoVault");
}

// ------------------------------------------------------------------ tests ---

#[cfg(test)]
mod tests {
    use super::*;

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
    fn envelope_wrap_unwrap_and_password_change() {
        let master = random_key();
        let mut meta = Meta {
            salt: String::new(),
            verifier: String::new(),
            wrapped_master: None,
            recovery: None,
        };
        rewrap_master(&mut meta, "first password", &master).unwrap();
        assert_eq!(master_from_password("first password", &meta).unwrap(), master);
        assert!(master_from_password("wrong password", &meta).is_err());
        // Password change re-wraps the same master key.
        rewrap_master(&mut meta, "second password", &master).unwrap();
        assert!(master_from_password("first password", &meta).is_err());
        assert_eq!(master_from_password("second password", &meta).unwrap(), master);
    }

    #[test]
    fn v1_meta_still_unlocks() {
        // v1 layout: master derived directly from password, no wrapped_master.
        let salt = [7u8; 16];
        let master = derive_key("legacy password", &salt).unwrap();
        let meta = Meta {
            salt: hex::encode(salt),
            verifier: hex::encode(encrypt(&master, VERIFIER_PLAINTEXT).unwrap()),
            wrapped_master: None,
            recovery: None,
        };
        assert_eq!(master_from_password("legacy password", &meta).unwrap(), master);
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
    fn media_kind_detection() {
        assert!(is_video_name("clip.MOV"));
        assert!(is_video_name("movie.mp4"));
        assert!(!is_video_name("photo.heic"));
        assert!(is_media_path(std::path::Path::new("/x/IMG_1.HEIC")));
        assert!(is_media_path(std::path::Path::new("/x/v.m4v")));
        assert!(!is_media_path(std::path::Path::new("/x/notes.txt")));
    }
}
