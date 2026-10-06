# Photo ingestion

## Requirement and ownership

The user requested fixes for six ingestion flaws on 2026-09-09: deletion of
changed Inbox sources, unsynced encrypted object writes, viewer actions using
a stale list index, hidden import and cleanup failures, suppressed retries
after temporary failures, and missed library refreshes during manual imports.
Owner: PhotoVault maintainers. This record covers Import, Finder drops, manual
Process Inbox, and the automatic watcher. Vault and object formats stay the same.

## Intended behavior and acceptance examples

- Replace or modify a queued Inbox file after reading it. Preserve bytes that
  do not match the imported source, including duplicate files. A replacement
  created at the original pathname during cleanup must remain untouched.
- Fail an encrypted object write, object sync, or index save. Keep the Inbox
  source and report failure. Count only committed imports, retaining earlier
  successes if a later file fails.
- Fail source cleanup after a successful import. Report the successful import
  and a separate cleanup failure, with the retained file location.
- Fail a destination write, then repair it without modifying the source.
  Automatic ingestion retries after a bounded delay. Permanent decode failures
  wait for a source change or an explicit manual retry.
- Open photo A and ingest photo B that sorts before A. Keep showing A, and make
  Delete, Favorite, Rename, and Export still target A. Preserve playback and
  zoom when the open media has not changed. If the item leaves the view,
  explicitly display the adjacent photo, or close if the view is empty.
- Start Export, let ingestion reorder the list while the save dialog is open,
  then confirm. Export the originally selected photo.
- Let an Inbox event arrive while Process Inbox or Import is running. Refresh
  after the operation settles, including zero-item results and rejections.
- Return only failures or mixed results. Display counts, filenames, reasons,
  and cleanup failures in a report retaining the latest 50 batches. Clear
  sensitive UI on lock and reject late results from the previous unlocked session.

## Contracts and verification plan

`ImportResult` is shared by command results and `inbox-imported` events:
`imported`, `skipped`, `failed`, `cleanup_failed`, and `issues`. Each issue has
`name`, `reason`, `stage` as `import` or `cleanup`, and `retryable`.
Use only synthetic media in test fixtures. Never include personal photos or
credentials in fixtures or this record.

- Backend: `cd src-tauri && cargo test --locked`. Use temporary vaults and
  synthetic files to exercise persistence, cleanup, replacement, and retries.
- Frontend: `node --test tests/sorting.test.cjs tests/ingestion.test.cjs`.
  Run shipped inline functions with synthetic photos and mocked Tauri commands.
- Browser: load the actual HTML with a synthetic Tauri bridge. Exercise real
  DOM refresh, viewer actions, report rendering, dismissal, and lock clearing.
- Final: inspect the task diff and run `git diff --check`. Have a fresh reviewer
  examine correctness, security, scope, tests, and maintainability.

## Implementation

`collect_files` records discovery failures for requested files and folders.
`read_source` captures the content hash and identity from an open file, checking
metadata before and after the read. Files over 4 GB (`MAX_IMPORT_BYTES`) fail
permanently before any read. `read_capped` reads at most the checked size and
reports a failed allocation as a temporary "Not enough memory" failure.
`import_one` verifies the source again after preparing media with
`hash_source`, a streamed blake3 hash plus metadata, so the file isn't loaded
twice. Encryption and decryption work in place. `write_object` syncs the
encrypted original and thumbnail; the objects directory is synced before an index commit can succeed.

Both manual and automatic Inbox processing call `run_inbox_import`.
`commit_inbox_batch` counts committed files, then `cleanup_inbox_source` verifies
the encrypted copy before `delete_inbox_source` claims the source pathname into
a private `Pending import ...` folder at the Inbox root. Cleanup compares the
claimed file against the imported source proof. Changed files and failed
cleanup remain recoverable and scanner-visible, with the location in the report.
The original pathname is never unlinked after the claim.

`run_inbox_import` imports loose files first, then each zip in turn: it is
extracted by `unzip_inbox_archive`, its media imported, and that group's
batch and duplicate filings saved before the next zip is unpacked. If the
index can't be saved (a batch, a new album, or a duplicate filing), remaining
zips are left untouched and reported "Not attempted". Entries go to a hidden
`.photovault-unzip-*` staging folder, which is synced, marked with a `.photovault-album` file holding the zip's name,
then renamed to a visible folder at the Inbox root. Staging left by a crash is
discarded on the next pass. `__MACOSX`, `.DS_Store`, and marker entries are
skipped, so an archive can't choose its own album. Hidden files and nested zips
are extracted but not imported, and the scanner ignores zips under a marker.
Extracted files take the entry's UTC extended timestamp, capped at the current
time, as modified and (on macOS) creation time. The basic zip time has no time
zone and is ignored.
The archive is hashed (streamed blake3) from the opened file before
extraction. The zip is removed through `claim_and_remove`, the same
rename-then-verify claim used for media, only if it has no symlink entries and
the claimed file still matches that identity and hash. Unsafe paths, damage,
archives without media, more than 20 GB or 100,000 entries, and errors that
waiting won't fix fail permanently and keep the zip. Process Inbox retries
them. A full, quota-limited, or read-only disk is marked `slow_retry` instead. `inbox_album_name` finds the nearest marker above
each file, and `ensure_album` reuses a same-named album (ignoring case) or
creates one. New photos carry the album in their index entry. Duplicates are
filed in batches by `file_inbox_duplicates` before their sources are removed.
The watcher emits `inbox-progress` (`{done, total}`) at the start, at most
every 500ms, and at the end, plus `{0, 0}` before each zip is unpacked. The UI
shows it as a toast. It emits `library-changed` (null payload) after each saved
batch, each newly created album, and each duplicate filing; the UI reloads
albums and photos on that, so a large zip appears in batches. A failed refresh
stays pending and retries after 1s, 2s, 4s, up to 30s, reporting once per
streak. `loadAlbums` and `loadGrid` drop stale responses and keep the current
lists on failure.

`InboxRetry` distinguishes permanent input failures from temporary I/O and
helper failures. Temporary failures use increasing delays capped at 60 seconds.
`slow_retry` failures wait 10 minutes, then 30 minutes per repeat. The 4 GB
cap is permanent. Background work doesn't count as user activity: the watcher
claims imports with `claim_background_import`, `flush_batch` doesn't touch
`last_activity`, and `list_photos`, `list_albums`, and thumbnail requests use
`background_key`. A file that keeps failing can't hold the vault open past
auto-lock. Full media requests still count, so playing a video does.
Retry bookkeeping follows a retained recovery path without resetting attempts.
For failures at the original path, it retains the scanned signature so a
replacement remains eligible for processing.
The `inbox-imported` event carries failure-only and mixed outcomes too.

In `ui/index.html`, `viewerId` and `syncViewer` keep the displayed media tied to
its photo across `renderPhotos`. `loadGrid` discards stale or previous-session
responses. `drainImportRefresh` processes queued watcher refreshes after manual
operations settle. `reportImport` renders issue text without HTML and retains
50 reports. `clearVaultUI` invalidates pending work and clears metadata and
reports on lock. Export captures the photo ID before opening the save dialog.

## Verification evidence

Verified on macOS with Node v22.23.2:

- Passed: 40 Rust tests, including 14 new ingestion regressions. After the final
  failed-batch clearing safeguard, the focused batch-failure regression passed
  again.
- Passed: 37 frontend tests, comprising 19 ingestion and 18 sorting tests.
- Passed: browser checks using the actual HTML and a synthetic Tauri bridge.
  Baseline checks reproduced the wrong viewer target after insertion, hidden
  failures, and a dropped refresh during Process Inbox. Updated checks covered
  stable viewer identity and zoom, action targets, adjacent-photo navigation,
  queued refreshes, mixed and failure-only reports, literal issue text,
  dismissal, lock clearing, stale results, and narrow-window scrolling.
- Passed: fresh independent review of correctness, security, scope, tests, and
  maintainability, including final checks of retry signatures and aborted batches.
- Passed: `git diff --check`.
- Passed: `npm run build` after the final code change. The macOS bundle is
  `src-tauri/target/release/bundle/macos/PhotoVault.app`. The build reports the
  existing unused `derive_key` warning.

Baseline: commit `0deab25` plus existing uncommitted work. Before-task source
copies and diff are in `/tmp/photovault-ingestion-baseline/`. The prior review
ran 26 Rust tests successfully. These results do not verify the new changes.
Task-only source diffs, the frontend test log, and the final release build log
are saved in that temporary directory.

## Limits

Native app launch, real-media ingestion, and abrupt power-loss testing were not
run. Browser checks mocked native commands; Rust checks used temporary fixtures.
No personal vault or Inbox was accessed, and the installed app was not replaced.

Cleanup protects pathname replacements by claiming and verifying the source
before removal. It cannot prevent a separate process from writing through an
already-open file descriptor after final verification. Strict coordination with
such writers requires their cooperation.
