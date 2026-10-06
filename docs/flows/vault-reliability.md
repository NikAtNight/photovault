# Vault reliability

## Requirement and ownership

On 2026-09-09, the user requested a commit and push of the existing work,
then implementation of five reliability fixes in parallel. The checkpoint is
`34211b4`, pushed to `origin/main`. Owner: PhotoVault maintainers.

Scope: preserve photos after index recovery, validate and stage backups and
restores, report failed operations accurately, prevent simultaneous vault
writers, and produce identifiable locally signed builds. The optional
appearance selector is outside these five fixes.

## Intended behavior and acceptance checks

- Corrupt the latest index after an import. Unlock from the previous index
  without deleting newer objects. Recovery protection survives saves and
  restarts, skips automatic trash expiry, and remains visible while unlocked.
- Back up a library while other operations are requested. Capture a consistent
  snapshot or reject the backup clearly. Fail missing required files and
  preserve the previous destination on a failed write.
- Restore a malformed, incomplete, or interrupted archive. Keep the original
  active vault intact. Stage and validate before switching directories, retain
  the previous vault, and roll back failed installation.
- Fail an album, favorite, rename, tag, date-scan, or settings save. Restore
  the previous in-memory values (`edit_library`), so a later save can't
  persist the failed change.
- Leave a failing file in the Inbox past the auto-lock time. The vault locks
  and the UI shows the login screen.
- Generate a recovery key, then lock or press Escape before clicking Done.
  `recovery_generate` only holds the new key in memory and returns it with an
  id; `recovery_confirm(id)` saves exactly that key, and only if the vault
  hasn't locked and unlocked since (`Vault.session`). Lock drops the pending
  key, the old key keeps working, nothing shows over the lock screen, and lock
  clears typed passwords. The UI shows only the latest Generate response.
- Fail the recovery key save. If nothing was replaced, any old key still
  works. If the new meta file landed but the directory sync failed
  (`WriteError::Unconfirmed`), the new key counts as saved and the modal
  warns to keep it.
- Fail a settings save. `save_settings` replaces `settings.json` atomically.
  If the replace didn't happen, memory rolls back and the old file stays. If
  it happened but the directory sync failed, the new settings count as saved.
  Turning Touch ID off saves the setting before deleting the keychain item.
- Let the vault go idle and then trigger any command. Whichever path wipes the
  key, `lock_tick` sends `vault-locked` within about 5 seconds unless the UI
  already knows (`lock_unreported`). Mouse or keyboard input on an idle vault
  locks it instead of reviving it.
- Fail trash/restore persistence. Keep memory and disk consistent, retain
  selection, and show failure. Mixed bulk exports report exported and failed
  counts with safely rendered filenames and reasons.
- Start another updated app using the same vault. Reject the second writer
  before vault or Inbox work starts. Release ownership on process exit,
  including crashes, and preserve it across restore directory swaps.
- Build locally. `npm run build` produces a bundle that passes
  `codesign --verify --deep --strict`. Settings shows version/build identity
  that changes when app inputs change.

## Validation plan

Use temporary synthetic fixtures only. Do not launch the real app or access
personal vault or Inbox contents.

- `node --test tests/*.test.cjs` for UI results and session boundaries.
- `cd src-tauri && cargo test --locked` for recovery, persistence, archives,
  and real subprocess lock contention/release.
- Synthetic browser bridge for recovery notices, export failure details,
  Settings build identity, and lock clearing.
- Final release build/signature verification and independent code review.

Baseline passed: 40 frontend tests and 40 Rust tests before the checkpoint.
Implementation evidence will be recorded after integration.

## Process ownership

`instance_lock::acquire` opens `vault.lock` in the app data directory and takes
an exclusive OS file lock. Tauri owns the open handle for the process lifetime.
The file remains in place after exit; ownership depends on the OS lock, not
the existence of a stale file. Startup acquires ownership before creating or
reading the vault and before starting Inbox work. Contention shows a dialog
and exits the new copy.

`native::another_copy_running` also checks for an already-running bundle with
the same identifier. This covers an older installed copy that was started
first. An old build launched afterward does not obey the new file lock, so
quit or replace old copies before testing. The OS lock guarantees exclusion
between updated builds. It remains outside the directory replaced by restore.

The implementation uses the standard library's file-lock API, available since
Rust 1.89. Focused tests use real child processes to verify contention, release
after normal exit and termination, and retention across vault directory swaps.

## Recovery and archives

`load_index` records fallback in an encrypted index field and a durable
`recovery-required` marker before allowing unlock. `finish_unlock` and
`sweep_orphans` pause automatic deletion while that state is present.
`persist_index` preserves the known-good backup during recovery. The UI checks
`recovery_status` after refresh and clears the notice on lock.

The new `backup` module serves both backup and restore commands. Backup validates
required objects, copies mutable metadata, and hard-links immutable encrypted
objects into a private snapshot while holding the metadata and vault locks.
It releases those locks before streaming the ZIP. Concurrent deletion cannot
remove the captured inodes. The temporary archive replaces the destination
only after writing and syncing; a subsequent directory-sync error explicitly
identifies the already-published archive.

Restore requires a locked vault. It validates paths, file types, required
entries, metadata, and the new manifest's file sizes and checksums in a staging
directory. On macOS it atomically swaps directories, retains the previous vault,
and attempts rollback if directory synchronization fails. Checksums detect
corruption, not malicious repackaging. Legacy archives lack checksums, and
completeness against their encrypted index cannot be proved before unlock.
A process crash may leave an encrypted temporary snapshot directory.

## Operation results and build identity

`changePhotos` is shared by trash, restore, and permanent deletion. Rejected
commands preserve selection and do not show success. Session guards discard
late dialogs, results, and progress after lock. `appendOperationReport` renders
both import and export details with text nodes, retaining at most 50 operations.
Bulk exports return per-file failures and counts, reserve filenames without
replacing existing exports, and identify any partial output after a write error.
Object removal after a committed purge remains best-effort; it is not a secure
physical-erasure guarantee.

`build.rs` hashes app inputs and includes the Git revision in `PHOTOVAULT_BUILD_ID`.
`get_build_info` exposes the configured version and identity in Settings. Tests
cover unchanged inputs, edited UI/Rust/config, added source files, and source
archives without Git. Tauri's macOS signing identity is `-`, so local release
builds apply ad hoc signing without a manual repair step.

The new modules separate archive handling and OS ownership from Tauri command
wiring. Shared helpers reuse operation-result rendering for imports/exports and
mutation handling across trash/restore/purge.

## Integration evidence

The first combined run passed 57 frontend tests and 69 Rust tests. A fresh
review then identified a post-rename directory-sync failure that needed an
additional regression before release validation.

Synthetic browser checks passed for failed trash retaining selection, visible
failure messages, mixed export counts and literal HTML-like filenames, recovery
notice visibility, Settings build details, and clearing reports/notices on lock.
The bridge reported no JavaScript errors. These checks used mock native commands;
the personal vault and Inbox were not accessed and the native app was not launched.

An unresolved `index.rollback` journal now blocks backup capture. The backup
regressions verify that neither an uncommitted candidate index nor a marker
inspection error replaces an existing archive.

Index saves now write and sync an encrypted `index.rollback` before replacing
the primary index. A failed commit retains that journal and blocks further
saves. On the next unlock, recovery preserves the proposed generation as
`index.unconfirmed`, enables recovery protection, and restores the previous
index before loading it. Persistent sync errors refuse unlock while preserving
the recovery files. Once the new index is durable and the journal is removed,
a final cleanup-sync failure does not incorrectly report the mutation as failed.
A crash that resurrects the journal can trigger conservative recovery; both
metadata generations and all objects remain available.

Final automated validation passed: 76 Rust tests and 57 frontend tests, with
no failures or skipped tests. This includes three post-rename save regressions
and 18 archive tests. Archives round-trip the encrypted unconfirmed index
variants and reject malformed recovery filenames. Fresh independent reviews
found no remaining blockers after these corrections. `git diff --check` passed.

`npm run build` passed and Tauri signed the bundle with identity `-`.
`codesign --verify --deep --strict --verbose=2` passed without manual signing.
Version: `0.2.0`; build: `34211b4b2924-c1772f3d7761f39a`.
Bundle: `src-tauri/target/release/bundle/macos/PhotoVault.app`.
The existing unused `derive_key` compiler warning remains. Notarization was
skipped for this local ad hoc build. Native app launch and the startup dialog
were not tested against personal data; subprocess file-lock tests did run.

The initial checkpoint was committed and pushed before implementation. After
validation, the user requested a separate commit and push of all five fixes
and this verification record.
