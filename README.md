# PhotoVault

A password-locked photo & video library for macOS, built with Tauri
(Rust + native webview). Every file is encrypted at rest — browsing the data
folder in Finder or the CLI shows only random-named opaque blobs.

## Security model

- **Envelope encryption:** a random 32-byte **master key** encrypts every
  photo, video, thumbnail, and the library index with **AES-256-GCM**
  (random 12-byte nonce per file, authenticated). The master key is *wrapped*
  (encrypted) by keys derived from your credentials:
  - your **password** → KEK via **scrypt** (N=2¹⁵, r=8, p=1, random 16-byte
    salt). Changing the password just re-wraps the master key — instant, no
    re-encryption of the library.
  - an optional **recovery key** (random 64-hex-char code, shown once) that
    can unlock the vault and reset the password if you forget it.
  - optionally **Touch ID**: the master key is stored in the macOS login
    keychain (encrypted at rest by the OS, released only to this app) and
    reads are gated behind a biometric prompt.
- **On disk:** `~/Library/Application Support/com.talix.photovault/vault/`
  contains `meta.json` (salt + wrapped keys + verifier), `index.enc`,
  `index.bak` (previous index generation, crash safety) and
  `objects/<random-hex>` blobs. No filenames, no extensions, no readable EXIF.
- **In memory:** the master key lives only inside the app process while
  unlocked and is zeroized on lock — via the Lock button, **auto-lock** after
  inactivity (1 min – 1 hour or off; default 15 min), or automatically when
  **the Mac sleeps or the screen locks**. Decrypted media is served to the UI
  over an in-process `pvmedia://` protocol — never written to disk.
- **Screenshots & screen sharing** of the window are blocked by default
  (toggle in Settings).
- **No recovery without the recovery key:** if you forget the password and
  never generated a recovery key (or disabled it), the photos are gone.
  That's the point.
- Vaults created by older versions are migrated to envelope encryption
  automatically on first unlock (the old `meta.json` is kept as
  `meta.v1.bak`).

## Usage

- **Run the built app:** `src-tauri/target/release/bundle/macos/PhotoVault.app`
  (copy it to /Applications if you like).
- First launch asks you to create a password (min 8 characters) and offers a
  one-time **recovery key** — store it somewhere safe.
- **Import** via the Import menu or drag-and-drop files/folders from Finder
  (folders are walked recursively). Originals are stored losslessly.
  **Duplicate files are skipped** by content hash (toggle in Settings).
- **Formats:** JPEG, PNG, GIF, WebP, BMP, TIFF, **HEIC/HEIF** (iPhone photos,
  converted for thumbnails via macOS `sips`, originals kept), and **video**
  (MP4, MOV, M4V — poster frames via QuickLook, streamed with seeking).
- **Browse:** sidebar with **All Photos / Favorites / Videos / Recently
  Deleted / Albums**; grid or list view; sort by date added, **date taken**
  (EXIF), name, size, or type; **search** by filename (`/` focuses the box).
- **Select** multiple items (Select button, ⌘-click, shift-click, or Space
  with keyboard focus; ⌘A selects all) to favorite, add to an album, export,
  or delete together.
- **Viewer:** click any item — ← / → to browse, scroll or double-click to
  **zoom**, drag to pan, `f` favorites, `i` shows the info panel
  (size, dimensions, dates, albums), click the name to rename, ▶ starts a
  **slideshow**. Videos play inline with seeking.
- **Deleting moves items to Recently Deleted** for 30 days (undo from the
  toast, restore or Delete Forever from the trash view). **Delete All** and
  **Empty Trash** live in Settings.
- **Export** — a single item from the viewer, a selection, or **Export all**
  (Settings) to decrypt everything into a folder of your choosing.
- **Back up vault…** (Settings) writes a zip of the vault — everything inside
  stays encrypted, so it's safe to keep in cloud storage. To restore: quit the
  app and unzip it over the vault folder (path above).
- **PhotoVault Inbox** (`~/PhotoVault Inbox`) — save or download media into
  this folder and the app encrypts it into the vault and deletes the plaintext
  file, usually within a couple of seconds. If the app is locked or not
  running, files wait (unencrypted!) until the next unlock — the lock screen
  shows how many are waiting. Once unlocked, click **Process Inbox** to process
  waiting files immediately (the automatic watcher continues to run too).

## Settings

Auto-lock interval · lock on sleep/screen-lock · block screenshots & screen
sharing · skip duplicate imports · Touch ID unlock · change password ·
generate/disable recovery key · back up vault · backfill EXIF dates for old
imports · export all · empty trash · delete all.

## Development

```sh
npm install          # tauri CLI
npm run dev          # dev window with hot reload
npm run build        # release .app bundle
```

Backend tests: `cd src-tauri && cargo test`.

Notes:
- Touch ID uses the login keychain plus a LocalAuthentication prompt (the
  SEP-backed data-protection keychain needs Apple-issued signing
  entitlements, which locally built apps don't have). After rebuilding the
  app you may need to re-enable Touch ID once — ad-hoc signatures change per
  build and the keychain ACL is tied to them.
- HEIC decoding for thumbnails shells out to `/usr/bin/sips`; video poster
  frames to `/usr/bin/qlmanage`. Both ship with macOS.

## License

MIT — see [LICENSE](LICENSE).
