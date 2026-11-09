# iPhone sharing

PhotoVault on the Mac can send an album or a selection to a paired iPhone. The
phone gets an encrypted `.pvshare` file by AirDrop or USB and opens it in the
PhotoVault iPhone app, which unlocks with Face ID only. There is no syncing and
no network connection between the two.

This file is the contract between the Mac side (Rust, `src-tauri`) and the
iPhone app (Swift, `ios/`). Change both sides together.

## Threat model

- The phone's private key is a non-exportable P-256 key bound to its Secure
  Enclave, created with `.privateKeyUsage` and `.biometryCurrentSet` and no
  passcode alternative, using
  `SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])`.
  Removing the device passcode destroys the key. The app never sets
  `touchIDAuthenticationAllowableReuseDuration`. `.biometryCurrentSet` alone allows any biometry, so
  the app also requires Face ID hardware and enrollment
  (`LAContext.biometryType == .faceID`) before pairing or unlocking. The app
  uses a fresh `LAContext` for each unlock and invalidates it on lock.
  Re-enrolling Face ID invalidates the key, and the phone must pair again.
- The Mac decrypts each original fully in memory while writing a share, so
  a large video briefly needs about twice its size in RAM. Nothing goes to disk.
- ECDH output, derived keys, and decrypted media exist in app memory while
  unlocked. Both apps discard them on lock, and the phone also discards them
  when it enters the background. Protection assumes the OS and app aren't
  compromised.
- Shares give recipient confidentiality only. They don't authenticate the
  sender and don't prevent replay: anyone holding the phone's public key can
  make a valid share. The public key isn't secret, but the app only imports
  files the user opens, and treats every file as untrusted input.
- A `.pvshare` file is useless without the phone's key. Observers (a wrong
  AirDrop target, an iCloud Drive copy, a backup) see the format version, a
  stable recipient `key_id`, the ephemeral public key, salt, wrapped-key bytes,
  the manifest's offset and exact plaintext and ciphertext lengths, and the
  total file length. `key_id` links every share sent to the same phone. The
  manifest size roughly gives the item count and name lengths, and the file
  length shows how much media there is. Names, titles, item ids, dates, dimensions, and
  the per-item media references stay encrypted.
- Decrypted media lives only in memory on both sides. The Mac never writes
  plaintext to disk while sharing. The phone never saves to the Photos
  library, the camera roll, iCloud, or temporary files.
- Not covered: someone photographing the screen, and screenshots (iOS can't
  block them). The phone blanks its screen in the app switcher and while the
  screen is being captured.

## Primitives

Both sides use only these:

- P-256 ECDH. Public keys are 65-byte uncompressed X9.63 / SEC1 points
  (`0x04 || X || Y`). CryptoKit: `x963Representation`. Rust: `p256`. Keys
  are exactly 65 bytes starting with `0x04`; readers reject anything else,
  including 33-byte compressed points that `from_sec1_bytes` would accept.
- HKDF-SHA256 (extract with salt, then expand with info), 32-byte output.
  CryptoKit: `SharedSecret.hkdfDerivedSymmetricKey`. Rust: `hkdf` + `sha2`.
- AES-256-GCM with 12-byte nonces and 16-byte tags appended to the
  ciphertext. CryptoKit: `AES.GCM`. Rust: `aes-gcm`.

- The ECDH input to HKDF is the fixed-width 32-byte big-endian shared
  x-coordinate, leading zeros kept. (CryptoKit's `SharedSecret` and
  `p256::ecdh::SharedSecret::raw_secret_bytes()` both give this.) X9.63 here
  names the public key encoding only, not a KDF.
- HKDF must run extract and expand: in Rust, `Hkdf::<Sha256>::new(Some(salt), shared)`
  then `expand(info)`. Never `from_prk(shared)`.
- Chunk bytes are `ciphertext || tag`. In CryptoKit that's
  `sealedBox.ciphertext + sealedBox.tag`, never `sealedBox.combined` (which
  starts with the nonce). The wrapped key includes its nonce exactly once, at
  the front.

`key_id` = lowercase hex of the first 8 bytes of SHA-256(public key bytes).

`verification code` = the first 16 bytes of SHA-256(public key bytes) as
uppercase hex in 8 groups of 4, separated by spaces (for example
`3F2A 9C01 ...`).

## Pairing file (`.pvpair`)

Made by the phone, sent to the Mac once. Plain JSON, UTF-8. It holds only a
public key.

```json
{
  "format": "photovault-pair",
  "version": 1,
  "label": "iPhone",
  "public_key": "<base64 standard, 65 bytes>",
  "key_id": "<16 hex chars>"
}
```

The Mac must reject a file whose `format` or `version` differs, whose public
key isn't a valid P-256 point, or whose `key_id` doesn't match the key.

The file's `key_id` proves nothing about who made it: an attacker who swaps
the file can swap the key and `key_id` together. So pairing needs a check the
user does by eye. The phone shows its verification code (and `key_id`) on
the pairing screen. The Mac computes the code from the file's public key itself, shows it,
and saves the pairing only after the user confirms the two match. The Mac
stores paired phones in the encrypted library index, never in plaintext.

## Share file (`.pvshare`)

All integers are little-endian unless noted. Every `offset` is relative to
the start of the blob area, which begins at byte `12 + header_len`. Readers
add that base.

```
magic        8 bytes   "PVSHARE1"
header_len   u32       length of the header JSON, at most 65,536
header       JSON      UTF-8, plaintext (see below)
blob area    ...       encrypted blobs, at the offsets the header and manifest give
```

Writers produce the item blobs in any order, then the manifest, then the
header. They may stage the blob area as ciphertext in a temp file and copy it
after the header. Plaintext never touches disk.

The file name is `PhotoVault-<8 random lowercase hex>.pvshare`. It never
includes the album title, item names, or dates, because AirDrop, Files, and
iCloud Drive show file names.

### Header (plaintext)

```json
{
  "version": 1,
  "key_id": "<16 hex chars, the phone's key>",
  "ephemeral_public_key": "<base64, 65 bytes>",
  "salt": "<base64, 32 random bytes>",
  "wrapped_key": "<base64: 12-byte nonce || AES-GCM ciphertext+tag of the 32-byte content key>",
  "manifest": { "offset": 0, "length": 0, "nonce_prefix": "<base64, 7 bytes>", "size": 0 }
}
```

Unwrapping the content key:

1. `shared = ECDH(phone private key, ephemeral_public_key)`. The Mac computes
   the same secret with its fresh ephemeral private key and the phone's
   public key, then throws the ephemeral key away.
2. `kek = HKDF-SHA256(ikm = shared, salt = salt,
   info = "photovault-share-v1" || ephemeral_public_key || phone_public_key, 32 bytes)`.
   The info string is the 19 ASCII bytes followed by the two raw 65-byte keys.
3. `content_key = AES-GCM-open(kek, nonce, ciphertext, aad = "PVSHARE1")`.

The content key is random per share file.

### Blobs (chunked AES-GCM)

The manifest, every thumbnail, and every original are separate blobs. A blob
is the plaintext split into 1 MiB (1,048,576-byte) chunks; the last chunk may
be shorter. An empty plaintext is one empty chunk. Each chunk is stored as
AES-GCM ciphertext+tag (chunk length + 16 bytes), back to back, with no length
prefixes.

- Chunk nonce (12 bytes) = `nonce_prefix` ||
  chunk index (u32, **big-endian**) || last flag (1 byte: `0x01` for the last
  chunk, `0x00` otherwise).
- `nonce_prefix` is 7 cryptographically random bytes, unique among all blobs
  under this content key, the manifest included. Writers regenerate on a
  collision. A content key is never reused for another share.
- AAD = the blob's id as UTF-8: `"manifest"` for the manifest,
  `"<item id>/original"` and `"<item id>/thumb"` for items.

A blob reference is `{ offset, length, nonce_prefix, size }`. `length` is the
ciphertext byte count, `size` the plaintext byte count. A reader can decrypt
any chunk on its own: chunk `i` starts at `offset + i * (1 MiB + 16)`.
Readers must, with checked integer arithmetic:

- Let `n = max(1, ceil(size / 1048576))`. Require `n <= 2^32` and
  `length == size + 16 * n`.
- Require `header_len <= 65536` and the manifest's `size <= 16 MiB`.
- Require every blob range (`12 + header_len + offset + length`) to lie
  inside the file.
- Number chunks from 0 without wrapping. Set the last flag to `0x01` exactly
  when `i == n - 1`. The reader derives the flag; it never trusts one.
- Authenticate each chunk before exposing any of its plaintext. A blob is
  complete only once all `n` chunks authenticate.
- Reject a manifest with duplicate item ids, an unknown `version`, or a
  `kind` other than `"photo"` or `"video"`.
- Decode media defensively. Serve video to AVPlayer through an
  `AVAssetResourceLoaderDelegate` that decrypts only the chunks a byte range
  needs. Never write a temp file.
- Treat every header field as untrusted input: check the version, base64
  lengths (65-byte keys, 32-byte salt, 7-byte prefixes), and that the
  ephemeral key is a valid P-256 point.

### Manifest (encrypted blob)

```json
{
  "version": 1,
  "title": "Album name",
  "created": 1767225600.0,
  "items": [
    {
      "id": "1",
      "name": "IMG_0001.HEIC",
      "kind": "photo",
      "taken": 1767225600.0,
      "width": 4032,
      "height": 3024,
      "original": { "offset": 0, "length": 0, "nonce_prefix": "...", "size": 0 },
      "thumb": { "offset": 0, "length": 0, "nonce_prefix": "...", "size": 0 }
    }
  ]
}
```

- `id` is a share-local id (`"1"`, `"2"`, ...), never the vault's object id.
- `kind` is `"photo"` or `"video"`. `taken`, `width`, `height`, and `thumb` may
  be absent or null. Thumbnails are JPEG.
- Items keep the order the Mac sends them in: the order shown in the Mac grid.

## Interop fixture

`ios/PhotoVaultTests/Fixtures/fixture.pvshare` is checked in. The Rust test
`share::tests::write_ios_fixture` (`cargo test write_ios_fixture -- --ignored`)
checks that the current writer produces the same content. After a format
change, rewrite it with `PV_WRITE_FIXTURE=1 cargo test write_ios_fixture -- --ignored`. It is encrypted to the test-only
P-256 private key with scalar

```
c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721
```

and contains title `"Fixture"` and two items:

1. id `"1"`, name `"pattern.bin"`, kind `"photo"`, original = 2,621,440 bytes
   where byte `i` is `i % 251` (three chunks, the last one short), and a thumb
   of 10 bytes `0..9`.
2. id `"2"`, name `"empty.mov"`, kind `"video"`, an empty original (one empty
   chunk) and no thumb.

The Swift tests decrypt it with a software key built from that scalar. This
key is for tests only and must never ship in an app build.
