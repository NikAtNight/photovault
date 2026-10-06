# PhotoVault

A password-locked photo & video library for macOS, built with Tauri
(Rust + native webview). Every file is encrypted at rest — browsing the data
folder in Finder or the CLI shows only random-named opaque blobs.

## Security model

- **Envelope encryption:** a random 32-byte **master key** encrypts every
  photo, video, thumbnail, and the library index with **AES-256-GCM**
  (random 12-byte nonce per file, authenticated). The master key is *wrapped*
  (encrypted) by keys derived from your credentials:
  - your **password** → KEK via **scrypt** (N=2¹⁷, r=8, p=1, random 16-byte
    salt; vaults made with the older N=2¹⁵ move up when you change the
    password or reset it with the recovery key). Changing the password just re-wraps the master key — instant, no
    re-encryption of the library.
  - an optional **recovery key** (random 64-hex-char code, shown once) that
    can unlock the vault and reset the password if you forget it. A new key
    takes effect only when you click **I've saved it**; until then any old key
    keeps working.
  - optionally **Touch ID**: the master key is stored in the macOS login
    keychain (encrypted at rest by the OS, released only to this app) and
    reads are gated behind a biometric prompt.
- **On disk:** `~/Library/Application Support/com.talix.photovault/vault/`
  contains `meta.json` (salt + wrapped keys + verifier), `index.enc`,
  `index.bak` (previous index generation, crash safety) and
  `objects/<random-hex>` blobs. No filenames, no extensions, no readable EXIF.
- **In memory:** the master key lives only inside the app process while
  unlocked and is zeroized on lock — via the Lock button, **auto-lock** after
  inactivity (1 min – 1 hour or off; default 15 min). Mouse and keyboard use,
  opening photos, and playing video count as activity; Inbox imports, library
  refreshes, and thumbnail loads don't. It also locks automatically when
  **the Mac sleeps or the screen locks**. Decrypted media is served to the UI
  over an in-process `pvmedia://` protocol — never written to disk.
- **Screenshots & screen sharing** of the window are blocked by default
  (toggle in Settings).
- **No recovery without the recovery key:** if you forget the password and
  never generated a recovery key (or disabled it), the photos are gone.
  That's the point.
- Vaults created by older versions are migrated to envelope encryption
  automatically on first unlock. A `meta.v1.bak` left by earlier builds is
  removed after the next successful unlock, password change, or recovery
  change.

## Usage

- **Appearance:** follows macOS light or dark mode, with a translucent sidebar,
  grouped toolbar controls, and system typography. Command-F focuses search.
  The photo list scrolls horizontally in narrow windows so every sorting
  column stays available. Styling uses the existing Tauri webview.
- **Run the built app:** `src-tauri/target/release/bundle/macos/PhotoVault.app`
  (copy it to /Applications if you like).
- First launch asks you to create a password (min 8 characters) and offers a
  one-time **recovery key** — store it somewhere safe.
- **Import** via the Import menu or drag-and-drop files/folders from Finder
  (folders are walked recursively). Originals are stored losslessly.
  **Duplicate files are skipped** by content hash (toggle in Settings).
  Files are imported **in name order** (numeric-aware, so `IMG_2` lands before
  `IMG_10`), a folder at a time.
- **Import straight into an album:** drop onto an album in the sidebar, or
  drop anywhere while browsing an album — new photos are filed into it, and
  duplicates you already own are added to the album too. Importing from the
  Import menu while browsing an album does the same. (Create an album with the
  **+** next to *Albums*; it opens right away, ready for a drop.)
- **Import and export results** retain the latest 50 operations until dismissed
  or the vault locks. Import reports list imported, duplicate, failed, and cleanup-failed
  counts, with file paths and reasons.
  Failed imports keep their source files. Cleanup failures mean the encrypted
  copy may be saved while removing the original still needs attention.
- **Formats:** JPEG, PNG, GIF, WebP, BMP, TIFF, **HEIC/HEIF** (iPhone photos,
  converted for thumbnails via macOS `sips`, originals kept), and **video**
  (MP4, MOV, M4V — poster frames via QuickLook, streamed with seeking).
- **Browse:** sidebar with **All Photos / Favorites / Videos / Recently
  Deleted / Albums**. Drag its right edge to resize it (double-click the edge
  to reset); grid or list view; sort by date added, **date taken**
  (EXIF), name, size, or type; **search** by filename (`/` focuses the box).
- **Sort by multiple columns:** in list view, click **Added**, then
  **Shift-click Name**. Photos group by local calendar day, then sort by name
  within each day. Names use numeric order, so `House_2` precedes `House_10`.
  Heading arrows show direction and numbers show priority. Shift-click an
  active column to reverse its direction. A plain click starts a new
  single-column sort, and clicking it again reverses it. Date-only sorting
  uses the exact timestamp. The default remains newest day first, then name.
  Preferences persist and apply to grid, list, and viewer navigation. Grid
  view keeps the original sort dropdown; choose a new option to reset to one
  column. Duplicates keep their existing grouping by file contents.
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
  Bulk exports report successful and failed files separately, with reasons.
  Existing destination files are preserved. A failed write can leave a partial
  file; its error identifies the path to check before retrying.
- **Back up vault…** (Settings) captures a consistent encrypted snapshot, then
  writes a ZIP with checksums. Locking remains available while the ZIP is written.
  **Restore from backup** on the lock screen validates a staged copy before
  replacing the vault and retains the previous vault in a sibling directory.
  Legacy archives receive structural checks but lack the new checksums.
- **Index recovery:** if PhotoVault falls back to an older index, a persistent
  notice appears. Automatic orphan cleanup and trash expiration pause to protect
  newer files. Back up the vault before attempting recovery. Restoring a healthy
  backup clears this state; dismissing a notice cannot disable protection.
- **One running copy:** updated builds prevent simultaneous writers to the same
  vault. Quit or replace older installed copies before testing, since old builds
  do not participate in the new file lock.
- **PhotoVault Inbox** (`~/PhotoVault Inbox`) — save or download media into
  this folder and the app encrypts it into the vault and deletes the plaintext
  file, usually within a couple of seconds — a batch that arrives together is
  imported in name order. If the app is locked or not
  running, files wait (unencrypted!) until the next unlock — the lock screen
  shows how many are waiting. Once unlocked, click **Process Inbox** to process
  waiting files immediately (the automatic watcher continues to run too).
  Temporary failures retry automatically with increasing delays, up to one
  minute. A full or read-only disk retries after 10 minutes, then every 30.
  Files over 4 GB aren't imported yet; they stay in place with a report and
  aren't retried until they change. Photos show up in the library as each
  batch is saved, not only when the whole pass ends. Changed or replaced sources are preserved rather than discarded;
  check the result report for their location. Recovery folders named
  `Pending import ...` stay inside Inbox and are scanned on subsequent passes.
  Encrypted files are synced before the index is saved and originals removed.
- **Zip files in the Inbox** are unzipped into a folder of the same name, and
  their photos and videos go into an album named after the zip (`Summer
  Trip.zip` files into *Summer Trip*). An existing album with that name, in any
  letter case, is reused. Photos you already own are added to the album too.
  Zips are handled one at a time, so the first zip's photos appear before the
  next one is unpacked. The zip is deleted once it's extracted, unless its
  contents changed during extraction, in which case it's kept. Files that aren't imported (text,
  JSON, hidden files, zips inside the zip) stay in the extracted folder.
  A zip placed inside an extracted folder is left alone. Extracted files keep
  the zip's UTC timestamps when it has them (Finder and `zip` write these).
  Zips that are damaged,
  password protected, hold no media, contain paths escaping the folder, or
  expand past 20 GB stay in the Inbox with a report. So do zips holding
  symlinks, after their other files are extracted.

## Settings

Auto-lock interval · lock on sleep/screen-lock · block screenshots & screen
sharing · skip duplicate imports · Touch ID unlock · change password ·
generate/disable recovery key · back up vault · backfill EXIF dates for old
imports · export all · empty trash · delete all.

## Development

Requires Rust 1.89 or later. Local builds use ad hoc signing automatically.
Settings shows the app version and a build ID derived from source inputs.

```sh
npm install          # tauri CLI
npm run dev          # dev window with hot reload
npm run build        # release .app bundle
```

App icon source: `app-icon.png`. Regenerate platform icons with
`npm run tauri -- icon app-icon.png`, then rebuild the app.
Artwork prompt and provenance: [app icon](docs/app-icon.md).

Frontend tests: `node --test tests/*.test.cjs` with Node 22 or later.
Backend tests: `cd src-tauri && cargo test`.
Behavior and verification: [photo sorting](docs/flows/photo-sorting.md) and
[photo ingestion](docs/flows/photo-ingestion.md).
Reliability contracts and checks: [vault reliability](docs/flows/vault-reliability.md).
Design and accessibility checks: [macOS appearance](docs/flows/macos-design.md).

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
