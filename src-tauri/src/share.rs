//! Writer for the iPhone sharing format in docs/iphone-sharing.md.
use super::{ExportResult, ImportProgress, PhotoInfo};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"PVSHARE1";
const CHUNK: usize = 1_048_576;
const MAX_PAIR: usize = 65_536;
const MAX_LABEL: usize = 64;
const MAX_HEADER: usize = 65_536;
const MAX_MANIFEST: usize = 16 * 1_048_576;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Device {
    pub label: String,
    pub public_key: String,
    pub key_id: String,
    pub added: f64,
}

#[derive(Deserialize)]
struct Pair {
    format: String,
    version: u32,
    label: String,
    public_key: String,
    key_id: String,
}

fn phone_key(encoded: &str) -> Result<PublicKey, String> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| "Invalid public key base64.")?;
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err("Public key must be a 65-byte uncompressed P-256 point.".into());
    }
    PublicKey::from_sec1_bytes(&bytes).map_err(|_| "Invalid P-256 point.".into())
}

pub(crate) fn read_pair(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_PAIR as u64 {
        return Err("Pairing file exceeds the 64 KiB limit.".into());
    }
    // Bound the read too, in case the file grows after the metadata check.
    let mut bytes = Vec::new();
    file.take(MAX_PAIR as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_PAIR {
        return Err("Pairing file exceeds the 64 KiB limit.".into());
    }
    Ok(bytes)
}

pub(crate) fn parse_pair(bytes: &[u8]) -> Result<Device, String> {
    if bytes.len() > MAX_PAIR {
        return Err("Pairing file exceeds the 64 KiB limit.".into());
    }
    let pair: Pair =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid pairing file: {e}"))?;
    if pair.format != "photovault-pair" || pair.version != 1 {
        return Err("Unsupported pairing format or version.".into());
    }
    let label = pair.label.trim();
    if label.chars().count() > MAX_LABEL {
        return Err("Phone label exceeds the 64-character limit.".into());
    }
    let key = phone_key(&pair.public_key)?;
    let digest = Sha256::digest(key.to_encoded_point(false).as_bytes());
    if pair.key_id != hex::encode(&digest[..8]) {
        return Err("Pairing key_id does not match the public key.".into());
    }
    Ok(Device {
        label: label.to_owned(),
        public_key: pair.public_key,
        key_id: hex::encode(&digest[..8]),
        added: super::now_secs(),
    })
}

#[derive(Serialize)]
pub(crate) struct PairPreview {
    label: String,
    key_id: String,
    pub code: String,
}

pub(crate) fn preview_pair(bytes: &[u8]) -> Result<PairPreview, String> {
    let device = parse_pair(bytes)?;
    let public = phone_key(&device.public_key)?;
    let digest = Sha256::digest(public.to_encoded_point(false).as_bytes());
    let code = digest[..16]
        .chunks(2)
        .map(hex::encode_upper)
        .collect::<Vec<_>>()
        .join(" ");
    Ok(PairPreview {
        label: device.label,
        key_id: device.key_id,
        code,
    })
}

#[derive(Clone, Serialize, Deserialize)]
struct Blob {
    offset: u64,
    length: u64,
    nonce_prefix: String,
    size: u64,
}
#[derive(Serialize, Deserialize)]
struct Header {
    version: u32,
    key_id: String,
    ephemeral_public_key: String,
    salt: String,
    wrapped_key: String,
    manifest: Blob,
}
#[derive(Serialize, Deserialize)]
struct Item {
    id: String,
    name: String,
    kind: String,
    taken: Option<f64>,
    width: Option<u32>,
    height: Option<u32>,
    original: Blob,
    thumb: Option<Blob>,
}
#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    title: String,
    created: f64,
    items: Vec<Item>,
}

fn nonce(prefix: &[u8], index: u32, last: bool) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..7].copy_from_slice(prefix);
    nonce[7..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

fn write_blob(
    file: &mut File,
    cipher: &Aes256Gcm,
    prefixes: &mut HashSet<[u8; 7]>,
    id: &str,
    bytes: &[u8],
) -> Result<Blob, String> {
    let mut prefix = [0; 7];
    loop {
        OsRng.fill_bytes(&mut prefix);
        if prefixes.insert(prefix) {
            break;
        }
    }
    let offset = file.stream_position().map_err(|e| e.to_string())?;
    let count = bytes.len().max(1).div_ceil(CHUNK);
    if count as u64 > u32::MAX as u64 + 1 {
        return Err("Blob has too many chunks.".into());
    }
    for i in 0..count {
        let chunk = &bytes[(i * CHUNK).min(bytes.len())..((i + 1) * CHUNK).min(bytes.len())];
        let nonce = nonce(&prefix, i as u32, i + 1 == count);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| "Cannot encrypt share chunk.")?;
        file.write_all(&encrypted).map_err(|e| e.to_string())?;
    }
    Ok(Blob {
        offset,
        length: bytes.len() as u64 + count as u64 * 16,
        nonce_prefix: STANDARD.encode(prefix),
        size: bytes.len() as u64,
    })
}

type Media = (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

pub(crate) fn write_share(
    dest: &Path,
    phone: &Device,
    title: String,
    entries: Vec<(String, PhotoInfo)>,
    mut result: ExportResult,
    mut load: impl FnMut(&str) -> Result<Media, String>,
    mut progress: impl FnMut(ImportProgress),
) -> Result<ExportResult, String> {
    let public = phone_key(&phone.public_key)?;
    // EphemeralSecret zeroizes its scalar on drop, including on errors.
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_encoded_point(false);
    let shared = ephemeral.diffie_hellman(&public);
    drop(ephemeral);
    let mut salt = [0; 32];
    OsRng.fill_bytes(&mut salt);
    let mut info = b"photovault-share-v1".to_vec();
    info.extend_from_slice(ephemeral_public.as_bytes());
    info.extend_from_slice(public.to_encoded_point(false).as_bytes());
    let mut kek = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes())
        .expand(&info, &mut *kek)
        .map_err(|_| "Cannot derive sharing key.")?;
    drop(shared);
    let content = Zeroizing::new(super::random_key());
    let mut wrap_nonce = [0; 12];
    OsRng.fill_bytes(&mut wrap_nonce);
    let mut wrapped = wrap_nonce.to_vec();
    wrapped.extend(
        Aes256Gcm::new_from_slice(&*kek)
            .map_err(|e| e.to_string())?
            .encrypt(
                Nonce::from_slice(&wrap_nonce),
                Payload {
                    msg: &*content,
                    aad: MAGIC,
                },
            )
            .map_err(|_| "Cannot wrap sharing key.")?,
    );
    let cipher = Aes256Gcm::new_from_slice(&*content).map_err(|e| e.to_string())?;
    let mut header = Header {
        version: 1,
        key_id: phone.key_id.clone(),
        ephemeral_public_key: STANDARD.encode(ephemeral_public.as_bytes()),
        salt: STANDARD.encode(salt),
        wrapped_key: STANDARD.encode(wrapped),
        manifest: Blob {
            offset: 0,
            length: 0,
            nonce_prefix: String::new(),
            size: 0,
        },
    };
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temp = parent.join(format!(".pvshare-{}.tmp", hex::encode(super::random_key())));
    let staging = parent.join(format!(
        ".pvshare-{}.blobs",
        hex::encode(super::random_key())
    ));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&staging)
        .map_err(|e| e.to_string())?;
    let written = (|| -> Result<(), String> {
        let mut prefixes = HashSet::new();
        let total = entries.len() + result.failed;
        let mut manifest = Manifest {
            version: 1,
            title,
            created: super::now_secs(),
            items: Vec::new(),
        };
        for (id, photo) in entries {
            progress(ImportProgress {
                done: result.exported + result.failed,
                total,
            });
            let (original, thumb) = match load(&id) {
                Ok(media) => media,
                Err(error) => {
                    result.failed(photo.name, error);
                    continue;
                }
            };
            let local = (manifest.items.len() + 1).to_string();
            let original = write_blob(
                &mut file,
                &cipher,
                &mut prefixes,
                &format!("{local}/original"),
                &original,
            )?;
            let thumb = thumb
                .map(|bytes| {
                    write_blob(
                        &mut file,
                        &cipher,
                        &mut prefixes,
                        &format!("{local}/thumb"),
                        &bytes,
                    )
                })
                .transpose()?;
            let kind = if super::is_video_name(&photo.name) {
                "video"
            } else {
                "photo"
            }
            .into();
            manifest.items.push(Item {
                id: local,
                name: photo.name,
                kind,
                taken: photo.taken,
                width: photo.width,
                height: photo.height,
                original,
                thumb,
            });
            result.exported += 1;
        }
        if result.exported == 0 {
            progress(ImportProgress { done: total, total });
            return Ok(());
        }
        let manifest_bytes =
            Zeroizing::new(serde_json::to_vec(&manifest).map_err(|e| e.to_string())?);
        if manifest_bytes.len() > MAX_MANIFEST {
            return Err("Share manifest exceeds the 16 MiB limit. Share fewer items.".into());
        }
        header.manifest = write_blob(
            &mut file,
            &cipher,
            &mut prefixes,
            "manifest",
            &manifest_bytes,
        )?;
        let json = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
        if json.len() > MAX_HEADER {
            return Err("Share header exceeds the 65536-byte limit.".into());
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        output.write_all(MAGIC).map_err(|e| e.to_string())?;
        output
            .write_all(&(json.len() as u32).to_le_bytes())
            .map_err(|e| e.to_string())?;
        output.write_all(&json).map_err(|e| e.to_string())?;
        file.rewind().map_err(|e| e.to_string())?;
        std::io::copy(&mut file, &mut output).map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temp, dest).map_err(|e| e.to_string())?;
        progress(ImportProgress { done: total, total });
        Ok(())
    })();
    drop(file);
    let cleanup = fs::remove_file(&staging);
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written?;
    cleanup.map_err(|e| {
        format!(
            "Share saved, but cannot remove encrypted staging file {}: {e}",
            staging.display()
        )
    })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{ecdh::diffie_hellman, SecretKey};

    fn test_photo() -> PhotoInfo {
        serde_json::from_value(serde_json::json!({ "name": "photo.jpg", "added": 1.0 })).unwrap()
    }
    fn secret() -> SecretKey {
        SecretKey::from_slice(
            &hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap(),
        )
        .unwrap()
    }
    fn pairing() -> serde_json::Value {
        let bytes = secret().public_key().to_encoded_point(false);
        serde_json::json!({ "format": "photovault-pair", "version": 1, "label": "Test iPhone",
            "public_key": STANDARD.encode(bytes.as_bytes()), "key_id": hex::encode(&Sha256::digest(bytes.as_bytes())[..8]) })
    }
    fn device() -> Device {
        parse_pair(&serde_json::to_vec(&pairing()).unwrap()).unwrap()
    }
    fn read_blob(bytes: &[u8], key: &[u8], id: &str, blob: &Blob) -> Result<Vec<u8>, String> {
        let count = blob.size.max(1).div_ceil(CHUNK as u64);
        if blob.length != blob.size + count * 16 {
            return Err("Invalid length".into());
        }
        let prefix = STANDARD
            .decode(&blob.nonce_prefix)
            .map_err(|e| e.to_string())?;
        if prefix.len() != 7 {
            return Err("Invalid prefix".into());
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for i in 0..count {
            let size = (blob.size.saturating_sub(i * CHUNK as u64)).min(CHUNK as u64) as usize;
            let offset = (blob.offset + i * (CHUNK as u64 + 16)) as usize;
            let chunk = bytes
                .get(offset..offset + size + 16)
                .ok_or("Truncated chunk")?;
            let mut n = prefix.clone();
            n.extend_from_slice(&(i as u32).to_be_bytes());
            n.push(if i + 1 == count { 1 } else { 0 });
            out.extend(
                cipher
                    .decrypt(
                        Nonce::from_slice(&n),
                        Payload {
                            msg: chunk,
                            aad: id.as_bytes(),
                        },
                    )
                    .map_err(|_| "Authentication failed")?,
            );
        }
        Ok(out)
    }
    fn read(bytes: &[u8], secret: &SecretKey) -> Result<(Manifest, Vec<Media>), String> {
        if bytes.get(..8) != Some(MAGIC) {
            return Err("Bad magic".into());
        }
        let len = u32::from_le_bytes(bytes.get(8..12).ok_or("Short header")?.try_into().unwrap())
            as usize;
        let header: Header = serde_json::from_slice(bytes.get(12..12 + len).ok_or("Short header")?)
            .map_err(|e| e.to_string())?;
        let bytes = &bytes[12 + len..];
        let ephemeral = phone_key(&header.ephemeral_public_key)?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
        let mut info = b"photovault-share-v1".to_vec();
        info.extend_from_slice(ephemeral.to_encoded_point(false).as_bytes());
        info.extend_from_slice(secret.public_key().to_encoded_point(false).as_bytes());
        let mut kek = [0; 32];
        Hkdf::<Sha256>::new(
            Some(&STANDARD.decode(header.salt).unwrap()),
            shared.raw_secret_bytes(),
        )
        .expand(&info, &mut kek)
        .unwrap();
        let wrapped = STANDARD.decode(header.wrapped_key).unwrap();
        let key = Aes256Gcm::new_from_slice(&kek)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&wrapped[..12]),
                Payload {
                    msg: &wrapped[12..],
                    aad: MAGIC,
                },
            )
            .map_err(|_| "Wrong key")?;
        let manifest: Manifest =
            serde_json::from_slice(&read_blob(bytes, &key, "manifest", &header.manifest)?)
                .map_err(|e| e.to_string())?;
        let media = manifest
            .items
            .iter()
            .map(|item| {
                Ok((
                    Zeroizing::new(read_blob(
                        bytes,
                        &key,
                        &format!("{}/original", item.id),
                        &item.original,
                    )?),
                    item.thumb
                        .as_ref()
                        .map(|b| {
                            read_blob(bytes, &key, &format!("{}/thumb", item.id), b)
                                .map(Zeroizing::new)
                        })
                        .transpose()?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok((manifest, media))
    }
    fn fixture(path: &Path) -> ExportResult {
        let entries = [("source-one", "pattern.bin"), ("source-two", "empty.mov")]
            .into_iter()
            .map(|(id, name)| {
                let mut photo = test_photo();
                photo.name = name.into();
                (id.into(), photo)
            })
            .collect();
        write_share(
            path,
            &device(),
            "Fixture".into(),
            entries,
            ExportResult::default(),
            |id| {
                Ok(if id == "source-one" {
                    (
                        Zeroizing::new((0..2_621_440).map(|i| (i % 251) as u8).collect()),
                        Some(Zeroizing::new((0..10).collect())),
                    )
                } else {
                    (Zeroizing::new(Vec::new()), None)
                })
            },
            |_| {},
        )
        .unwrap()
    }
    fn temporary() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pvshare-test-{}", hex::encode(crate::random_key())))
    }
    #[test]
    fn round_trip() {
        let path = temporary();
        let result = fixture(&path);
        assert_eq!((result.exported, result.failed), (2, 0));
        let (manifest, media) = read(&fs::read(&path).unwrap(), &secret()).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(manifest.title, "Fixture");
        assert_eq!(
            manifest
                .items
                .iter()
                .map(|i| (i.id.as_str(), i.name.as_str(), i.kind.as_str()))
                .collect::<Vec<_>>(),
            vec![("1", "pattern.bin", "photo"), ("2", "empty.mov", "video")]
        );
        assert_eq!(media[0].0.len(), 2_621_440);
        assert!(media[0]
            .0
            .iter()
            .enumerate()
            .all(|(i, b)| *b == (i % 251) as u8));
        assert_eq!(
            media[0].1.as_ref().unwrap().as_slice(),
            &(0..10).collect::<Vec<_>>()
        );
        assert!(media[1].0.is_empty());
        assert!(media[1].1.is_none());
    }
    #[test]
    fn tampering_fails() {
        let path = temporary();
        fixture(&path);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();
        let mut flipped = bytes.clone();
        flipped[12 + u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize + 5] ^= 1;
        assert!(read(&flipped, &secret()).is_err());
        let mut swapped = bytes.clone();
        let start = 12 + u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let size = CHUNK + 16;
        for i in 0..size {
            swapped.swap(start + i, start + size + i);
        }
        assert!(read(&swapped, &secret()).is_err());
        let (manifest, _) = read(&bytes, &secret()).unwrap();
        let original = &manifest.items[0].original;
        let end = start + (original.offset + original.length) as usize;
        assert!(read(&bytes[..end - 1], &secret()).is_err());
        // Preserve the manifest, but remove one byte from the final original chunk.
        let mut truncated = bytes.clone();
        truncated.remove(end - 1);
        assert!(read(&truncated, &secret()).is_err());
        assert!(read(&bytes, &SecretKey::random(&mut OsRng)).is_err());
    }
    #[test]
    fn pairing_validation() {
        assert_eq!(device().key_id.len(), 16);
        let preview = preview_pair(&serde_json::to_vec(&pairing()).unwrap()).unwrap();
        let public = secret().public_key().to_encoded_point(false);
        let expected = hex::encode_upper(&Sha256::digest(public.as_bytes())[..16]);
        assert_eq!(preview.code.replace(' ', ""), expected);
        assert_eq!(
            preview.code.split(' ').map(str::len).collect::<Vec<_>>(),
            vec![4; 8]
        );
        for (field, value) in [
            ("format", serde_json::json!("other")),
            ("version", serde_json::json!(2)),
            ("key_id", serde_json::json!("0000000000000000")),
            ("public_key", serde_json::json!("!")),
            ("public_key", serde_json::json!(STANDARD.encode([4; 65]))),
            (
                "public_key",
                serde_json::json!(
                    STANDARD.encode(secret().public_key().to_encoded_point(true).as_bytes())
                ),
            ),
        ] {
            let mut pair = pairing();
            pair[field] = value;
            assert!(
                parse_pair(&serde_json::to_vec(&pair).unwrap()).is_err(),
                "{field}"
            );
        }
        assert!(parse_pair(b"not JSON").is_err());
    }
    #[test]
    fn empty_shares_preserve_destination_and_clean_staging() {
        let dir = temporary();
        fs::create_dir(&dir).unwrap();
        let path = dir.join("share.pvshare");
        for existing in [false, true] {
            if existing {
                fs::write(&path, b"previous").unwrap();
            }
            for entries in [vec![], vec![("gone".into(), test_photo())]] {
                let failed = entries.len();
                let mut events = Vec::new();
                let result = write_share(
                    &path,
                    &device(),
                    "Empty".into(),
                    entries,
                    ExportResult::default(),
                    |_| Err("Missing original".into()),
                    |p| events.push((p.done, p.total)),
                )
                .unwrap();
                assert_eq!((result.exported, result.failed), (0, failed));
                assert_eq!(events.last(), Some(&(failed, failed)));
                if existing {
                    assert_eq!(fs::read(&path).unwrap(), b"previous");
                } else {
                    assert!(!path.exists());
                }
                assert_eq!(fs::read_dir(&dir).unwrap().count(), usize::from(existing));
            }
        }
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn mixed_share_reports_progress_and_failures() {
        let path = temporary();
        let mut events = Vec::new();
        let result = write_share(
            &path,
            &device(),
            "Mixed".into(),
            vec![("gone".into(), test_photo()), ("ok".into(), test_photo())],
            ExportResult::default(),
            |id| {
                if id == "gone" {
                    Err("Missing original".into())
                } else {
                    Ok((Zeroizing::new(vec![1]), None))
                }
            },
            |p| events.push((p.done, p.total)),
        )
        .unwrap();
        assert_eq!((result.exported, result.failed), (1, 1));
        assert_eq!(events, vec![(0, 2), (1, 2), (2, 2)]);
        assert_eq!(
            read(&fs::read(&path).unwrap(), &secret())
                .unwrap()
                .0
                .items
                .len(),
            1
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pairing_size_and_label_limits() {
        let path = temporary();
        // An oversized non-JSON file must fail the size check first.
        fs::write(&path, vec![b'x'; MAX_PAIR + 1]).unwrap();
        assert!(read_pair(&path).unwrap_err().contains("64 KiB"));
        assert!(parse_pair(&vec![b'x'; MAX_PAIR + 1])
            .err()
            .unwrap()
            .contains("64 KiB"));
        let mut pair = pairing();
        pair["label"] = serde_json::json!(format!("  {} ", "📱".repeat(64)));
        let mut bytes = serde_json::to_vec(&pair).unwrap();
        bytes.resize(MAX_PAIR, b' ');
        fs::write(&path, &bytes).unwrap();
        let device = parse_pair(&read_pair(&path).unwrap()).unwrap();
        assert_eq!(device.label, "📱".repeat(64));
        assert_eq!(preview_pair(&bytes).unwrap().label, device.label);
        pair["label"] = serde_json::json!("📱".repeat(65));
        let bytes = serde_json::to_vec(&pair).unwrap();
        assert!(parse_pair(&bytes).err().unwrap().contains("64-character"));
        assert!(preview_pair(&bytes).err().unwrap().contains("64-character"));
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn chunk_contract_and_unique_prefixes() {
        let path = temporary();
        let mut file = File::create(&path).unwrap();
        let key = [9; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut prefixes = HashSet::new();
        let data = vec![7; CHUNK + 8];
        let blob = write_blob(&mut file, &cipher, &mut prefixes, "1/original", &data).unwrap();
        let empty = write_blob(&mut file, &cipher, &mut prefixes, "2/original", &[]).unwrap();
        assert_eq!(prefixes.len(), 2);
        assert_ne!(blob.nonce_prefix, empty.nonce_prefix);
        drop(file);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(read_blob(&bytes, &key, "1/original", &blob).unwrap(), data);
        assert!(read_blob(&bytes, &key, "2/original", &empty)
            .unwrap()
            .is_empty());
        assert!(read_blob(
            &bytes[..blob.length as usize - 1],
            &key,
            "1/original",
            &blob
        )
        .is_err());
        let mut wrong_size = blob.clone();
        wrong_size.size -= 1;
        assert!(read_blob(&bytes, &key, "1/original", &wrong_size).is_err());
        assert!(read_blob(&bytes, &[8; 32], "1/original", &blob).is_err());
        assert!(read_blob(&bytes, &key, "2/original", &blob).is_err());
        // The first chunk's tag was sealed as non-final. Declaring it final must fail.
        let mut early_end = blob.clone();
        early_end.size = CHUNK as u64;
        early_end.length = CHUNK as u64 + 16;
        assert!(read_blob(&bytes, &key, "1/original", &early_end).is_err());
    }
    #[test]
    fn manifest_limit_preserves_destination_and_cleans_staging() {
        let dir = temporary();
        fs::create_dir(&dir).unwrap();
        let path = dir.join("share.pvshare");
        fs::write(&path, b"previous").unwrap();
        let error = write_share(
            &path,
            &device(),
            "x".repeat(MAX_MANIFEST),
            vec![("one".into(), test_photo())],
            ExportResult::default(),
            |_| Ok((Zeroizing::new(vec![1]), None)),
            |_| {},
        )
        .err()
        .unwrap();
        assert!(error.contains("16 MiB"));
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn devices_persist_roll_back_and_clear_with_collections() {
        let dir = temporary();
        fs::create_dir(&dir).unwrap();
        let key = [3; 32];
        let mut vault = crate::tests::test_vault(dir.clone(), Some(key));
        let device = device();
        let added = device.added;
        let id = device.key_id.clone();
        crate::edit_library(&mut vault, &key, |v| {
            v.collections.devices.insert(id.clone(), device);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            crate::load_index(&vault, &key).unwrap().collections.devices[&id].label,
            "Test iPhone"
        );
        let stored = crate::load_index(&vault, &key).unwrap().collections.devices[&id].clone();
        assert_eq!(stored.key_id, id);
        assert_eq!(stored.added, added);
        let result: Result<(), String> = crate::edit_library(&mut vault, &key, |v| {
            v.collections.devices.clear();
            Err("Simulated edit failure".into())
        });
        assert!(result.is_err());
        assert!(vault.collections.devices.contains_key(&id));
        crate::clear_vault_contents(&mut vault, &key).unwrap();
        assert!(crate::load_index(&vault, &key)
            .unwrap()
            .collections
            .devices
            .is_empty());
        crate::wipe_vault(&mut vault);
        assert!(vault.collections.devices.is_empty());
        // This directory contains only encrypted test index files.
        for entry in fs::read_dir(&dir).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        fs::remove_dir(dir).unwrap();
    }
    #[test]
    #[ignore]
    fn write_ios_fixture() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ios/PhotoVaultTests/Fixtures/fixture.pvshare");
        // PV_WRITE_FIXTURE=1 rewrites the checked-in fixture after a format change.
        // Otherwise check that a fresh writer output decrypts to the same content.
        if std::env::var_os("PV_WRITE_FIXTURE").is_some() {
            fixture(&path);
            return;
        }
        let generated = temporary();
        fixture(&generated);
        let (expected, expected_media) = read(&fs::read(&path).unwrap(), &secret()).unwrap();
        let (actual, actual_media) = read(&fs::read(&generated).unwrap(), &secret()).unwrap();
        fs::remove_file(generated).unwrap();
        assert_eq!(actual.title, expected.title);
        assert_eq!(actual.items.len(), expected.items.len());
        for (a, b) in actual.items.iter().zip(&expected.items) {
            assert_eq!((&a.id, &a.name, &a.kind), (&b.id, &b.name, &b.kind));
        }
        for (a, b) in actual_media.iter().zip(&expected_media) {
            assert_eq!(a.0.as_slice(), b.0.as_slice());
            assert_eq!(a.1.as_deref(), b.1.as_deref());
        }
    }
}
