# PhotoVault

A password-locked photo and video library for macOS, built with Tauri (Rust and
the system webview). Everything is encrypted on disk. The data folder holds only
random-named blobs: no filenames, no extensions, no EXIF.

There's also an iPhone app that views photos you share from the Mac. It unlocks
with Face ID only and never touches your Photos library or iCloud.

## How it's secured

- A random master key encrypts every file and the library index with
  AES-256-GCM. Your password unlocks it through scrypt. An optional recovery
  key and Touch ID can unlock it too.
- The key lives only in memory while unlocked. The app locks on demand, after
  inactivity (15 minutes by default), and when the Mac sleeps or the screen
  locks.
- Decrypted media goes straight to the window and is never written to disk.
  Screenshots and screen sharing of the window are blocked by default.
- Forget the password without a recovery key and the photos are gone. That's
  the point.

The vault lives in `~/Library/Application Support/com.talix.photovault/vault/`.

## What it does

- **Import** by drag and drop, the Import menu, or the `~/PhotoVault Inbox`
  folder. Inbox files are encrypted and the originals deleted within seconds.
  Folders and zips in the Inbox become albums.
- **Formats:** JPEG, PNG, GIF, WebP, BMP, TIFF, HEIC, MP4, MOV, M4V.
- **Organize** with albums, folders of albums, smart albums, favorites, and
  tags. Duplicates are skipped by content hash.
- **Browse** in a grid or list, sorted by date, name, size, or type. Jump to a
  year, search by name, and select many items at once.
- **View** full screen with arrow keys, zoom, an info panel, and a slideshow.
- **Delete** to Recently Deleted, which keeps items for 30 days.
- **Export** single items, a selection, or everything. **Back up** the vault to
  a ZIP and restore it from the lock screen.

## iPhone sharing

1. In the iPhone app, create a pairing key and AirDrop the `.pvpair` file to
   your Mac.
2. On the Mac, open Settings > Your iPhone > Pair iPhone and check that the
   codes match.
3. Select photos or an album and choose Share to iPhone. AirDrop the
   `.pvshare` file to the phone and open it in PhotoVault.

Shares are encrypted to the phone's Secure Enclave key, so only that phone can
open them. Details: [sharing format and threat model](docs/iphone-sharing.md).
Building the phone app: [ios/README.md](ios/README.md).

## Development

Needs Rust 1.89+ and Node 22+.

```sh
npm install
npm run dev     # dev window with hot reload
npm run build   # release app in src-tauri/target/release/bundle/macos/
```

Tests: `node --test tests/*.test.cjs` and `cd src-tauri && cargo test`.

After a rebuild you may need to turn Touch ID on again, because local builds
are signed ad hoc and the keychain entry is tied to the signature.

More detail lives in [docs/flows](docs/flows): ingestion, sorting, vault
reliability, macOS design, and iPhone sharing. App icon notes are in
[docs/app-icon.md](docs/app-icon.md).

## License

MIT. See [LICENSE](LICENSE).
