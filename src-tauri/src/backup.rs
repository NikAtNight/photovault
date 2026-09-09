use super::*;
use std::path::Path;

const MANIFEST: &str = "backup-manifest.json";
const RECOVERY_MARKER: &str = "recovery-required";

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct FileDigest {
    size: u64,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u8,
    files: HashMap<String, FileDigest>,
}

// Only directories/files created by this operation are owned by this guard.
struct TemporaryPath {
    path: PathBuf,
    keep: bool,
}
impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if self.path.is_dir() {
            let _ = fs::remove_dir_all(&self.path);
        } else {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn is_unconfirmed_index(name: &str) -> bool {
    name == "index.unconfirmed"
        || name
            .strip_prefix("index (")
            .and_then(|suffix| suffix.strip_suffix(").unconfirmed"))
            .is_some_and(|counter| {
                counter
                    .as_bytes()
                    .first()
                    .is_some_and(|b| (b'1'..=b'9').contains(b))
                    && counter.bytes().all(|b| b.is_ascii_digit())
            })
}

pub(super) fn safe_entry(name: &str) -> bool {
    if name.contains("..") || name.starts_with('/') || name.contains('\\') {
        return false;
    }
    matches!(
        name,
        "meta.json" | "meta.bak" | "settings.json" | "index.enc" | "index.bak"
    ) || name == MANIFEST
        || name == RECOVERY_MARKER
        || is_unconfirmed_index(name)
        || name == "objects/"
        || name
            .strip_prefix("objects/")
            .is_some_and(|n| !n.is_empty() && !n.contains('/'))
}

fn copy_hashed(mut input: impl Read, mut output: impl Write) -> Result<FileDigest, String> {
    let mut hash = blake3::Hasher::new();
    let mut size = 0;
    let mut buf = [0; 65536];
    loop {
        let n = input.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        hash.update(&buf[..n]);
        size += n as u64;
    }
    Ok(FileDigest {
        size,
        hash: hash.finalize().to_hex().to_string(),
    })
}

fn regular_file(path: &Path) -> Result<fs::File, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("{} is not a regular file.", path.display()));
    }
    fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn validated_metadata(dir: &Path) -> Result<(), String> {
    let meta = read_meta(dir)?;
    if hex::decode(&meta.salt)
        .map_err(|e| e.to_string())?
        .is_empty()
        || hex::decode(&meta.verifier)
            .map_err(|e| e.to_string())?
            .len()
            < 28
    {
        return Err("The backup has invalid vault metadata.".into());
    }
    scrypt::Params::new(meta.n, meta.r, meta.p, 32).map_err(|e| e.to_string())?;
    for wrapping in [meta.wrapped_master, meta.recovery].into_iter().flatten() {
        if hex::decode(wrapping).map_err(|e| e.to_string())?.len() != 60 {
            return Err("The backup has an invalid wrapped key.".into());
        }
    }
    Ok(())
}

pub(super) fn write_backup(
    dest: &Path,
    state: &Mutex<Vault>,
    mut progress: impl FnMut(ImportProgress),
) -> Result<usize, String> {
    let meta_mutex = vlock(state).meta_lock.clone();
    let _meta_guard = meta_lock(&meta_mutex);
    let mut vault = vlock(state);
    let mut key = vault.active_key().ok_or("locked")?;
    if vault.importing {
        return Err("Wait for the import to finish before backing up.".into());
    }
    if vault
        .dir
        .join("index.rollback")
        .try_exists()
        .map_err(|e| format!("Cannot check the vault's unfinished update: {e}"))?
    {
        return Err(
            "The vault has an unfinished update. Lock and unlock it before backing up.".into(),
        );
    }
    // The metadata lock blocks password changes/unlock. The vault lock blocks
    // index/object mutations, and imports are rejected while their writes run.
    validated_metadata(&vault.dir)?;
    let index_source = match fs::symlink_metadata(vault.index_path()) {
        Ok(_) => vault.index_path(),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && vault.dir.join(RECOVERY_MARKER).is_file() =>
        {
            vault.index_bak_path()
        }
        Err(e) => return Err(format!("Cannot read index.enc: {e}")),
    };
    let mut current = Vec::new();
    regular_file(&index_source)?
        .read_to_end(&mut current)
        .map_err(|e| e.to_string())?;
    let data = decrypt(&key, &current)
        .and_then(|b| parse_index(&b))
        .or_else(|_| {
            let previous = fs::read(vault.index_bak_path()).map_err(|e| e.to_string())?;
            parse_index(&decrypt(&key, &previous)?)
        })?;
    for id in data.photos.keys().chain(vault.photos.keys()) {
        if !safe_entry(&format!("objects/{id}")) || id.ends_with(".t") {
            return Err("The index contains an invalid photo identifier.".into());
        }
        for name in [id.clone(), format!("{id}.t")] {
            let file = regular_file(&vault.objects_dir().join(&name))?;
            if file.metadata().map_err(|e| e.to_string())?.len() < 28 {
                return Err(format!("The encrypted photo object {name} is incomplete."));
            }
        }
    }
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
    if parent.starts_with(fs::canonicalize(&vault.dir).map_err(|e| e.to_string())?) {
        return Err("Save the backup outside the vault directory.".into());
    }
    let mut names = vec!["meta.json".to_string(), "index.enc".to_string()];
    for name in ["meta.bak", "settings.json", "index.bak", RECOVERY_MARKER] {
        match fs::symlink_metadata(vault.dir.join(name)) {
            Ok(_) => names.push(name.into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Cannot inspect {name}: {e}")),
        }
    }
    // Interrupted saves can leave encrypted candidate indexes for recovery.
    // Preserve each generation alongside the objects it may describe.
    for entry in fs::read_dir(&vault.dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if let Some(name) = entry
            .file_name()
            .to_str()
            .filter(|name| is_unconfirmed_index(name))
        {
            names.push(name.to_string());
        }
    }
    for entry in fs::read_dir(vault.objects_dir()).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Invalid object filename.")?;
        names.push(format!("objects/{name}"));
    }
    names.sort();
    // Objects are immutable after import. Keep their inodes alive with hard
    // links, and copy mutable metadata, while holding the snapshot locks.
    // Release both locks before copying large media into the ZIP so manual
    // and system lock requests remain responsive.
    let snapshot_path = vault
        .dir
        .with_file_name(format!(".vault-backup-{}", random_id()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&snapshot_path).map_err(|e| e.to_string())?;
    let snapshot = TemporaryPath {
        path: snapshot_path,
        keep: false,
    };
    fs::create_dir(snapshot.path.join("objects")).map_err(|e| e.to_string())?;
    for name in &names {
        if !safe_entry(name) {
            return Err(format!("Unexpected vault file: {name}"));
        }
        let captured = snapshot.path.join(name);
        if name == "index.enc" {
            // Recovery can supply a missing primary from index.bak. The
            // archive includes that generation and the recovery marker.
            fs::write(captured, &current).map_err(|e| e.to_string())?;
        } else {
            let mut source = regular_file(&vault.dir.join(name))?;
            if name.starts_with("objects/") {
                fs::hard_link(vault.dir.join(name), captured).map_err(|e| e.to_string())?;
            } else {
                let mut output = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(captured)
                    .map_err(|e| e.to_string())?;
                std::io::copy(&mut source, &mut output).map_err(|e| e.to_string())?;
            }
        }
    }
    key.zeroize();
    drop(data);
    drop(vault);
    drop(_meta_guard);
    let temp_path = parent.join(format!(".photovault-backup-{}.tmp", random_id()));
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|e| e.to_string())?;
    let temp = TemporaryPath {
        path: temp_path,
        keep: false,
    };
    let mut archive = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true);
    let total = names.len();
    let mut files = HashMap::new();
    for (i, name) in names.iter().enumerate() {
        archive.start_file(name, opts).map_err(|e| e.to_string())?;
        let digest = copy_hashed(regular_file(&snapshot.path.join(name))?, &mut archive)?;
        files.insert(name.clone(), digest);
        progress(ImportProgress { done: i + 1, total });
    }
    archive
        .start_file(MANIFEST, opts)
        .map_err(|e| e.to_string())?;
    let manifest =
        serde_json::to_vec(&Manifest { version: 1, files }).map_err(|e| e.to_string())?;
    archive.write_all(&manifest).map_err(|e| e.to_string())?;
    let file = archive.finish().map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&temp.path, dest).map_err(|e| e.to_string())?;
    sync_dir(&parent).map_err(|e| {
        format!(
            "The complete backup was written to {}, but syncing its directory failed: {e}",
            dest.display()
        )
    })?;
    Ok(total)
}

fn extract_validated(src: &Path, stage: &Path) -> Result<(), String> {
    let source = regular_file(src)?;
    let mut archive =
        zip::ZipArchive::new(source).map_err(|e| format!("Invalid backup archive: {e}"))?;
    let mut names = HashSet::new();
    for i in 0..archive.len() {
        let entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name();
        if !safe_entry(name)
            || !names.insert(name.to_string())
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            || (entry.is_dir() && name != "objects/")
        {
            return Err(format!("Unexpected or duplicate backup entry: {name}"));
        }
    }
    if !names.contains("meta.json") || !names.contains("index.enc") {
        return Err("The backup is missing meta.json or index.enc.".into());
    }
    let mut actual = HashMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage.join(&name))
            .map_err(|e| e.to_string())?;
        let digest = copy_hashed(&mut entry, &mut out)?;
        out.sync_all().map_err(|e| e.to_string())?;
        if name != MANIFEST {
            actual.insert(name, digest);
        }
    }
    let has_manifest = names.contains(MANIFEST);
    if has_manifest {
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(stage.join(MANIFEST)).map_err(|e| e.to_string())?)
                .map_err(|e| format!("Invalid backup manifest: {e}"))?;
        if manifest.version != 1 || manifest.files != actual {
            return Err("The backup is incomplete or does not match its manifest.".into());
        }
        // The manifest describes the archive snapshot, not the live vault.
        fs::remove_file(stage.join(MANIFEST)).map_err(|e| e.to_string())?;
    }
    validated_metadata(stage)?;
    let index_valid = |name: &str| actual.get(name).is_some_and(|d| d.size >= 28);
    if !index_valid("index.enc") && !index_valid("index.bak") {
        return Err("The backup has no complete encrypted index.".into());
    }
    if names.contains("settings.json") {
        serde_json::from_slice::<Settings>(
            &fs::read(stage.join("settings.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("Invalid backup settings: {e}"))?;
    }
    // A legacy archive has no manifest. Check all relationships that are
    // visible without a password; its encrypted index is checked on unlock.
    for (name, digest) in &actual {
        if !has_manifest && name.starts_with("objects/") {
            if digest.size < 28 && !names.contains(RECOVERY_MARKER) {
                return Err(format!("Incomplete encrypted object: {name}"));
            }
            if let Some(original) = name.strip_suffix(".t") {
                if !actual.contains_key(original) && !names.contains(RECOVERY_MARKER) {
                    return Err(format!("The backup is missing original {original}."));
                }
            }
        }
    }
    sync_dir(&stage.join("objects"))?;
    sync_dir(stage)
}

#[cfg(target_os = "macos")]
fn exchange_directories(a: &Path, b: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn renamex_np(a: *const std::ffi::c_char, b: *const std::ffi::c_char, flags: u32) -> i32;
    }
    let a = std::ffi::CString::new(a.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let b = std::ffi::CString::new(b.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // RENAME_SWAP, from the macOS SDK's sys/stdio.h. Both directories share a parent.
    if unsafe { renamex_np(a.as_ptr(), b.as_ptr(), 0x2) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(not(target_os = "macos"))]
fn exchange_directories(_: &Path, _: &Path) -> Result<(), String> {
    Err("Atomic vault replacement is supported on macOS.".into())
}

pub(super) fn restore(src: &Path, state: &Mutex<Vault>) -> Result<(), String> {
    let meta_mutex = vlock(state).meta_lock.clone();
    let _meta_guard = meta_lock(&meta_mutex);
    let mut vault = vlock(state);
    if vault.active_key().is_some() {
        return Err("Lock the vault before restoring a backup.".into());
    }
    if vault.importing {
        return Err("Wait for the import to finish before restoring a backup.".into());
    }
    let parent = vault
        .dir
        .parent()
        .ok_or("The vault has no parent directory.")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let stage_path = parent.join(format!("vault.pre-restore-{}", random_id()));
    fs::create_dir(&stage_path).map_err(|e| e.to_string())?;
    let mut stage = TemporaryPath {
        path: stage_path,
        keep: false,
    };
    fs::create_dir(stage.path.join("objects")).map_err(|e| e.to_string())?;
    extract_validated(src, &stage.path)?;
    let existed = vault.dir.try_exists().map_err(|e| e.to_string())?;
    if existed {
        exchange_directories(&stage.path, &vault.dir)?;
        // The guard now points to the old vault. Never delete it, even if a
        // subsequent sync or rollback fails.
        let old = stage.path.clone();
        stage.keep = true;
        if let Err(error) = sync_dir(parent) {
            match exchange_directories(&old, &vault.dir) {
                Ok(()) => {
                    let _ = sync_dir(parent);
                    return Err(format!("Restore could not be saved; the previous vault was restored: {error}"));
                }
                Err(rollback) => return Err(format!("Restore sync failed: {error}. Rollback failed: {rollback}. The previous vault is preserved at {}.", old.display())),
            }
        }
    } else {
        fs::rename(&stage.path, &vault.dir).map_err(|e| e.to_string())?;
        if let Err(error) = sync_dir(parent) {
            fs::rename(&vault.dir, &stage.path).map_err(|rollback| {
                format!("Restore sync failed: {error}; rollback failed: {rollback}")
            })?;
            return Err(error);
        }
    }
    wipe_vault(&mut vault);
    vault.settings = fs::read(vault.settings_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        root: PathBuf,
        state: Arc<Mutex<Vault>>,
        key: [u8; 32],
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("pv-backup-test-{}", random_id()));
            let dir = root.join("vault");
            fs::create_dir_all(dir.join("objects")).unwrap();
            let key = random_key();
            let mut vault = crate::tests::test_vault(dir, Some(key));
            let meta = Meta {
                salt: hex::encode([1; 16]),
                verifier: hex::encode(encrypt(&key, VERIFIER_PLAINTEXT).unwrap()),
                n: LEGACY_SCRYPT_LOG_N,
                r: DEFAULT_SCRYPT_R,
                p: DEFAULT_SCRYPT_P,
                wrapped_master: None,
                recovery: None,
            };
            write_meta(&vault.dir, &meta).unwrap();
            vault.photos.insert(
                "photo".into(),
                serde_json::from_str(r#"{"name":"photo.jpg","added":1}"#).unwrap(),
            );
            for name in ["photo", "photo.t"] {
                fs::write(
                    vault.objects_dir().join(name),
                    encrypt(&key, b"synthetic media").unwrap(),
                )
                .unwrap();
            }
            persist_index(&vault, &key).unwrap();
            Self {
                root,
                state: Arc::new(Mutex::new(vault)),
                key,
            }
        }
        fn archive(&self) -> PathBuf {
            let zip = self.root.join("backup.zip");
            write_backup(&zip, &self.state, |_| {}).unwrap();
            zip
        }
        fn lock(&self) {
            wipe_vault(&mut vlock(&self.state));
        }
        fn rewrite(
            &self,
            source: &Path,
            mut change: impl FnMut(&str, &mut Vec<u8>) -> bool,
        ) -> PathBuf {
            let mut source = zip::ZipArchive::new(fs::File::open(source).unwrap()).unwrap();
            let dest = self.root.join(format!("changed-{}.zip", random_id()));
            let mut out = zip::ZipWriter::new(fs::File::create(&dest).unwrap());
            for i in 0..source.len() {
                let mut entry = source.by_index(i).unwrap();
                let name = entry.name().to_string();
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                if change(&name, &mut bytes) {
                    out.start_file(name, zip::write::SimpleFileOptions::default())
                        .unwrap();
                    out.write_all(&bytes).unwrap();
                }
            }
            out.finish().unwrap();
            dest
        }
        fn assert_original(&self) {
            let vault = vlock(&self.state);
            assert!(vault.objects_dir().join("photo").is_file());
            assert_eq!(
                parse_index(&decrypt(&self.key, &fs::read(vault.index_path()).unwrap()).unwrap())
                    .unwrap()
                    .photos
                    .len(),
                1
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn backup_round_trip_preserves_old_vault_and_legacy_compatibility() {
        for legacy in [false, true] {
            let fixture = Fixture::new();
            let archive = fixture.archive();
            let archive = if legacy {
                fixture.rewrite(&archive, |name, _| name != MANIFEST)
            } else {
                archive
            };
            let sentinel = vlock(&fixture.state).dir.join("old-vault-sentinel");
            fs::write(&sentinel, b"preserve me").unwrap();
            fixture.lock();
            restore(&archive, &fixture.state).unwrap();
            fixture.assert_original();
            assert!(!sentinel.exists());
            let old = fs::read_dir(&fixture.root)
                .unwrap()
                .filter_map(Result::ok)
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("vault.pre-restore-")
                })
                .unwrap();
            assert_eq!(
                fs::read(old.path().join("old-vault-sentinel")).unwrap(),
                b"preserve me"
            );
            assert!(!vlock(&fixture.state).dir.join(MANIFEST).exists());
        }
    }

    #[test]
    fn backup_missing_original_or_index_preserves_destination() {
        for name in ["objects/photo", "index.enc", "meta.json"] {
            let fixture = Fixture::new();
            let dest = fixture.root.join("existing.zip");
            fs::write(&dest, b"previous backup").unwrap();
            fs::remove_file(vlock(&fixture.state).dir.join(name)).unwrap();
            assert!(
                write_backup(&dest, &fixture.state, |_| {}).is_err(),
                "{name}"
            );
            assert_eq!(fs::read(&dest).unwrap(), b"previous backup");
            assert!(!fs::read_dir(&fixture.root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|e| e
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".photovault-backup-")));
        }
    }

    #[test]
    fn backup_rejects_unreadable_optional_files_and_vault_destination() {
        let fixture = Fixture::new();
        let dest = vlock(&fixture.state).dir.join("bad.zip");
        assert!(write_backup(&dest, &fixture.state, |_| {}).is_err());
        fs::create_dir(vlock(&fixture.state).settings_path()).unwrap();
        assert!(write_backup(&fixture.root.join("bad.zip"), &fixture.state, |_| {}).is_err());
        assert!(!fixture.root.join("bad.zip").exists());
    }

    #[test]
    fn backup_and_restore_reject_active_imports() {
        let fixture = Fixture::new();
        let archive = fixture.archive();
        vlock(&fixture.state).importing = true;
        assert!(write_backup(&fixture.root.join("bad.zip"), &fixture.state, |_| {}).is_err());
        fixture.lock();
        assert!(restore(&archive, &fixture.state).is_err());
        fixture.assert_original();
    }

    #[test]
    fn backup_snapshot_survives_photo_removal_and_lock_during_zip_streaming() {
        let fixture = Fixture::new();
        let state = fixture.state.clone();
        let (start, started) = std::sync::mpsc::channel();
        let (attempt, attempted) = std::sync::mpsc::channel();
        let (done, completed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.recv().unwrap();
            attempt.send(()).unwrap();
            let mut vault = vlock(&state);
            vault.photos.remove("photo");
            persist_index(&vault, &vault.key.unwrap()).unwrap();
            fs::remove_file(vault.objects_dir().join("photo")).unwrap();
            fs::remove_file(vault.objects_dir().join("photo.t")).unwrap();
            wipe_vault(&mut vault);
            done.send(()).unwrap();
        });
        let archive = fixture.root.join("backup.zip");
        let mut first = true;
        write_backup(&archive, &fixture.state, |_| {
            if first {
                first = false;
                start.send(()).unwrap();
                attempted.recv_timeout(Duration::from_secs(2)).unwrap();
                completed.recv_timeout(Duration::from_secs(2)).unwrap();
            }
        })
        .unwrap();
        worker.join().unwrap();
        assert!(vlock(&fixture.state).key.is_none());
        assert!(!vlock(&fixture.state).objects_dir().join("photo").exists());
        fixture.lock();
        restore(&archive, &fixture.state).unwrap();
        fixture.assert_original();
    }

    #[test]
    fn backup_restore_rejects_missing_manifest_files_and_changed_bytes() {
        for missing in [false, true] {
            let fixture = Fixture::new();
            let source = fixture.archive();
            let changed = fixture.rewrite(&source, |name, bytes| {
                if name == "objects/photo" {
                    if missing {
                        return false;
                    }
                    bytes[20] ^= 1;
                }
                true
            });
            fixture.lock();
            assert!(restore(&changed, &fixture.state).is_err());
            fixture.assert_original();
            assert!(!fs::read_dir(&fixture.root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|e| e
                    .file_name()
                    .to_string_lossy()
                    .starts_with("vault.pre-restore-")));
        }
    }

    #[test]
    fn backup_restore_rejects_legacy_missing_index_and_original() {
        for absent in ["index.enc", "objects/photo"] {
            let fixture = Fixture::new();
            let source = fixture.archive();
            let changed = fixture.rewrite(&source, |name, _| name != MANIFEST && name != absent);
            fixture.lock();
            assert!(restore(&changed, &fixture.state).is_err());
            fixture.assert_original();
        }
    }

    #[test]
    fn backup_restore_sync_failure_rolls_back_without_deleting_either_vault() {
        let fixture = Fixture::new();
        let archive = fixture.archive();
        let sentinel = vlock(&fixture.state).dir.join("sentinel");
        fs::write(&sentinel, b"original vault").unwrap();
        fixture.lock();
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(fixture.root.clone()));
        let result = restore(&archive, &fixture.state);
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
        assert!(result.unwrap_err().contains("previous vault was restored"));
        assert_eq!(fs::read(sentinel).unwrap(), b"original vault");
        fixture.assert_original();
    }

    #[test]
    fn backup_preserves_recovery_marker_and_unindexed_objects() {
        let fixture = Fixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        fs::write(dir.join(RECOVERY_MARKER), b"recovery required").unwrap();
        fs::write(dir.join("objects/unindexed"), b"partial recovery remnant").unwrap();
        let archive = fixture.archive();
        fixture.lock();
        restore(&archive, &fixture.state).unwrap();
        assert!(dir.join(RECOVERY_MARKER).exists());
        assert_eq!(
            fs::read(dir.join("objects/unindexed")).unwrap(),
            b"partial recovery remnant"
        );
    }
    #[test]
    fn backup_restore_extraction_error_keeps_active_vault() {
        let fixture = Fixture::new();
        let archive = fixture.archive();
        let payload = fs::read(vlock(&fixture.state).objects_dir().join("photo")).unwrap();
        let mut bytes = fs::read(&archive).unwrap();
        let offset = bytes
            .windows(payload.len())
            .position(|window| window == payload)
            .unwrap();
        bytes[offset + 20] ^= 1;
        fs::write(&archive, bytes).unwrap();
        fixture.lock();
        assert!(restore(&archive, &fixture.state).is_err());
        fixture.assert_original();
        assert!(!fs::read_dir(&fixture.root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with("vault.pre-restore-")));
    }

    #[test]
    fn backup_restore_rejects_duplicate_entries_and_invalid_metadata() {
        let fixture = Fixture::new();
        let archive = fixture.archive();
        let invalid = fixture.rewrite(&archive, |name, bytes| {
            if name == "meta.json" || name == "meta.bak" {
                *bytes = b"invalid JSON".to_vec();
            }
            name != MANIFEST
        });
        fixture.lock();
        assert!(restore(&invalid, &fixture.state).is_err());
        fixture.assert_original();
        let mut bytes = fs::read(&archive).unwrap();
        let occurrences: Vec<usize> = bytes
            .windows(9)
            .enumerate()
            .filter_map(|(i, window)| (window == b"index.enc").then_some(i))
            .collect();
        for offset in occurrences {
            bytes[offset..offset + 9].copy_from_slice(b"meta.json");
        }
        fs::write(&archive, bytes).unwrap();
        assert!(restore(&archive, &fixture.state).is_err());
        fixture.assert_original();
    }

    #[test]
    fn backup_preserves_unindexed_crash_remnants_without_recovery_marker() {
        let fixture = Fixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        fs::write(dir.join("objects/unindexed"), b"partial").unwrap();
        let archive = fixture.archive();
        fixture.lock();
        restore(&archive, &fixture.state).unwrap();
        assert_eq!(fs::read(dir.join("objects/unindexed")).unwrap(), b"partial");
        fixture.assert_original();
    }
    #[test]
    fn backup_recovered_missing_primary_includes_a_restorable_index() {
        let fixture = Fixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        fs::rename(dir.join("index.enc"), dir.join("index.bak")).unwrap();
        fs::write(dir.join(RECOVERY_MARKER), b"recovery required").unwrap();
        let archive = fixture.archive();
        assert!(!dir.join("index.enc").exists());
        fixture.lock();
        restore(&archive, &fixture.state).unwrap();
        fixture.assert_original();
        assert!(dir.join(RECOVERY_MARKER).exists());
    }

    #[test]
    fn backup_late_sync_failure_reports_published_complete_archive() {
        let fixture = Fixture::new();
        let archive = fixture.root.join("backup.zip");
        fs::write(&archive, b"previous backup").unwrap();
        FAIL_DIRECTORY_SYNC
            .with(|failure| *failure.borrow_mut() = Some(fs::canonicalize(&fixture.root).unwrap()));
        let result = write_backup(&archive, &fixture.state, |_| {});
        FAIL_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
        assert!(result.unwrap_err().contains("complete backup was written"));
        fixture.lock();
        restore(&archive, &fixture.state).unwrap();
        fixture.assert_original();
    }
    #[test]
    fn backup_rejects_unresolved_index_transaction_without_publishing_candidate() {
        let fixture = Fixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        let previous = fs::read(dir.join("index.enc")).unwrap();
        fs::write(dir.join("index.rollback"), &previous).unwrap();
        let mut proposed: serde_json::Value =
            serde_json::from_slice(&decrypt(&fixture.key, &previous).unwrap()).unwrap();
        proposed["photos"]["photo"]["name"] = "uncommitted-name.jpg".into();
        let candidate = encrypt(&fixture.key, &serde_json::to_vec(&proposed).unwrap()).unwrap();
        fs::write(dir.join("index.enc"), &candidate).unwrap();
        let destination = fixture.root.join("existing.zip");
        fs::write(&destination, b"previous backup").unwrap();
        let error = write_backup(&destination, &fixture.state, |_| {}).unwrap_err();
        assert!(error.contains("unfinished update"));
        assert_eq!(fs::read(destination).unwrap(), b"previous backup");
        assert_eq!(fs::read(dir.join("index.enc")).unwrap(), candidate);
        assert_eq!(fs::read(dir.join("index.rollback")).unwrap(), previous);
    }

    #[cfg(unix)]
    #[test]
    fn backup_rejects_unreadable_transaction_state() {
        let fixture = Fixture::new();
        let marker = vlock(&fixture.state).dir.join("index.rollback");
        std::os::unix::fs::symlink("index.rollback", &marker).unwrap();
        let destination = fixture.root.join("backup.zip");
        let error = write_backup(&destination, &fixture.state, |_| {}).unwrap_err();
        assert!(error.contains("Cannot check"));
        assert!(!destination.exists());
    }
    #[test]
    fn backup_round_trip_preserves_all_unconfirmed_index_generations() {
        let fixture = Fixture::new();
        let dir = vlock(&fixture.state).dir.clone();
        fs::write(dir.join(RECOVERY_MARKER), b"recovery required").unwrap();
        let mut candidates = Vec::new();
        for _ in 0..3 {
            let path = unique_dest(&dir, "index.unconfirmed");
            let bytes = encrypt(&fixture.key, br#"{"photos":{},"albums":{}}"#).unwrap();
            fs::write(&path, &bytes).unwrap();
            candidates.push((path, bytes));
        }
        let archive = fixture.archive();
        fixture.lock();
        restore(&archive, &fixture.state).unwrap();
        fixture.assert_original();
        for (path, bytes) in candidates {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn backup_accepts_only_expected_unconfirmed_index_names() {
        for name in [
            "index.unconfirmed",
            "index (1).unconfirmed",
            "index (20).unconfirmed",
        ] {
            assert!(safe_entry(name), "{name}");
        }
        for name in [
            "index (0).unconfirmed",
            "index (01).unconfirmed",
            "index (-1).unconfirmed",
            "index ().unconfirmed",
            "index (a).unconfirmed",
            "index (1).unconfirmed/evil",
            "index (../1).unconfirmed",
            "index.unconfirmed.tmp",
            "index.rollback",
        ] {
            assert!(!safe_entry(name), "{name}");
        }
    }
}
