# Photo sorting

## Requirement and ownership

The user confirmed on 2026-09-09 that photos should sort by date first,
ignoring time, then by name within each day. Owner: PhotoVault maintainers.
This change covers frontend ordering and preferences. It does not change
vault metadata, import timestamps, authentication, or duplicate grouping.

## Behavior and implementation

In `ui/index.html`, list headings call `setSort` to edit `photoSort.rules`.
A plain click starts a single-column sort and toggles direction if that column
is already first. Shift-click appends a column or reverses an existing column
without changing its priority. Heading arrows and numbers show the order.
Enter and Space also activate focused headings, including with Shift held.
A short hint explains the interaction. There is no separate sorting panel.
The original dropdown is visible only in grid view and chooses a single sort.

`saveSort` stores preferences in `pv-sort-rules`, clears positional selection
anchors, and calls `renderPhotos`. `loadSort` validates stored preferences.
Legacy date sorts retain their direction and gain name as a secondary sort.
Legacy non-date sorts retain their column and direction.

`computeVisible` applies existing search and view filters, then calls
`sortPhotos`. Each column resolves ties from the preceding column. When a date
column has another column after it, it compares local calendar days, including
across daylight-saving changes. A final date column uses exact timestamps.
Date taken falls back to date added when capture metadata is absent. Names use
numeric comparison, so `House_2.jpg` precedes `House_10.jpg`. Photo ID resolves
remaining ties. The default is newest day first, then name ascending.

`renderPhotos` and `renderMore` use the resulting `visible` array for grid and
list views. `show` uses the same array for viewer navigation. Duplicate view
retains content grouping and disables sorting controls.

Malformed preferences fall back to a valid default. A failed preference write
shows a toast while the chosen order still applies in the current session.

## Verification

Verified against base commit `0deab25` plus uncommitted changes on macOS,
Node v22.23.2. Pre-existing README, UI, and backend edits were preserved.
Task-only UI and README diffs and test output are in the local evidence folder
`/tmp/photovault-sort-baseline/`. The Rust source checksum did not change.

- PASS: `node --test tests/sorting.test.cjs`, 18 tests. Covers date/name order,
  independent directions, single-column exact timestamps, local midnight,
  DST, missing EXIF, three-column priority, descending type, stable ties,
  persistence, legacy and invalid preferences, plain-click reset, Shift-click
  append and reverse, grid direction selection, filtered views, duplicate
  grouping, and parsing the full inline application script.
- PASS: `git diff --check`.
- PASS: browser checks with synthetic photos and stubbed Tauri commands.
  Covered plain-click reset, Shift-click add and reverse, five columns,
  numbered headings, keyboard activation, grid dropdown visibility and
  direction, grid/list/viewer agreement, duplicate-view guidance, and reload
  persistence. No application script errors occurred.
- NOT RUN: native Tauri launch, media loading, release build, and Rust tests.
  The frontend preview cannot serve the native `pvmedia` protocol. The backend
  was unchanged by this task. Native keyboard focus should be checked manually;
  the background browser preview cannot verify focus reliably.

To repeat the UI acceptance check in a development vault, use photos named
`House_1.jpg`, `House_2.jpg`, and `House_10.jpg`, added at different times on
one day, plus a photo added on an earlier day. In list view click Added to
choose the desired date direction, then Shift-click Name. Expect 1, 2, 10
within each day. Shift-click Name again to reverse names while retaining the
date direction. Click a heading without Shift to clear the other columns.
Switch views and advance in the viewer to confirm the same order is used.
