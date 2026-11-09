# iPhone sharing on the Mac

## Requirement and ownership

Owner: PhotoVault maintainers. The format and threat model are in
[the sharing contract](../iphone-sharing.md). The Mac writes shares and never
reads them. Syncing and sender authentication are outside this flow.

## Observed path

Settings > Your iPhone opens a `.pvpair` file. `pair_device_preview` validates
it and computes its key ID and verification code. The UI asks the user to
compare both with the phone's screen. `pair_device` reads the file again and
requires the confirmed code to match before saving through `edit_library`.
Devices live in `Collections` in the encrypted index. Re-pairing replaces the
same key ID. `list_devices` and `unpair_device` require an unlocked vault.
Unpairing does not revoke existing shares.

The selection button preserves grid order. Sidebar album share actions select
live members and apply the current sort. Smart albums use their current rules.
`sharePhotos` explains pairing when no phone exists, offers a picker for several
phones, and opens a save dialog with a random `PhotoVault-xxxxxxxx.pvshare` name.
The title and filenames stay inside the encrypted manifest.

`share_to_device` snapshots the key, phone, object path, and photo metadata while
holding the vault lock. It releases the lock before reading media. Missing and
trashed photos count as failures. It decrypts one original and its optional
thumbnail in memory at a time. A corrupt or unreadable item is reported and
skipped. `share::write_share` writes encrypted item blobs followed by the
manifest to a sibling staging file. It then writes a bounded header and copies
the encrypted blob area into a second temp file, syncs it, and renames it into
place. Offsets are relative to the blob area. Nonce prefixes are unique within
the share. A manifest over 16 MiB fails before publishing the destination.
Content keys, ephemeral scalars, and decrypted byte buffers are zeroized.

The UI retains result counts and failure reasons in the operation reports and
instructs the user to AirDrop the saved file. Lock wipes the pairing code,
phone labels, pickers, pending confirmations, and reports. Session checks
suppress late responses and prevent a pending dialog from starting a share
after lock. A share already writing can finish from its snapshot, like export.

## Verification and gaps

- `cd src-tauri && cargo test` covers the existing vault tests and the sharing
  round trip, independent test reader, tampering, chunk boundaries, pairing
  validation, device persistence and rollback, manifest limit, and temp cleanup.
- `node --test tests/*.test.cjs` exercises the shipped script with mocked DOM
  and Tauri commands. Cases cover ordering, album membership, phone selection,
  cancellation, pairing confirmation, failure counts, and lock races.
- `cd src-tauri && cargo test write_ios_fixture -- --ignored` writes
  `ios/PhotoVaultTests/Fixtures/fixture.pvshare` using the contract's test scalar
  and media patterns. The scalar exists only in Rust test code.

These checks do not establish native dialog behavior, a live AirDrop transfer,
or Swift interoperability. Those need app testing by the owning agents. The
implementation task forbids starting the Mac app or running the release build.
