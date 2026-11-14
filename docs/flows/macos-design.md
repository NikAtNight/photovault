# macOS appearance

## Requirement and ownership

On 2026-09-09, the user requested a macOS 26 redesign and confirmed that the
existing Tauri app should remain. Owner: PhotoVault maintainers.

The design follows Apple's [materials guidance](https://developer.apple.com/design/human-interface-guidelines/materials)
and [macOS 26 AppKit presentation](https://developer.apple.com/videos/play/wwdc2025/310/).
Translucent navigation and grouped controls sit above a plain media background.
The webview approximates these materials with CSS. It does not render native
Liquid Glass. The existing native title bar and window controls remain.

## Intended behavior

- Follow system light/dark appearance. Keep text and controls readable with
  reduced transparency, increased contrast, and reduced motion preferences.
- Dark appearance uses the Nocturne palette approved on 2026-11-09: charcoal
  page, sidebar, and panels (`#141617`, `#191c1d`, `#202324`), `#343939` lines,
  `#e8e8e2` text, `#9a9f9c` secondary text, a `#c6da96` accent that takes dark
  `#192017` text, and `#f5aaa0` for destructive actions. Light appearance keeps
  its blue accent with white text on it.
- Show photos as a dense contact sheet: square tiles with square corners and
  3px gaps.
- Every sidebar row shows a count: library rows and smart albums count items,
  albums count photos, and folders count the albums anywhere inside them.
  Counts follow imports, deletes, moves, favorites, and Inbox batches.
- Under the view title, show the item count. A view holding both photos and
  videos adds how many of each, such as "32,418 items · 30,312 photos ·
  2,106 videos".
- Keep toolbar actions, search, albums, and sorting usable at 1100 by 760 and
  the minimum 600 by 400 window size. A narrow list scrolls horizontally so
  names and sortable columns retain their width.
- Keep the selected library or album title, count, and sidebar counts current.
  Clear them on lock.
- Support keyboard sidebar navigation and visible focus. Control activation
  must not also invoke photo shortcuts. Keep focus within an open dialog.
- Preserve column sorting, selection, viewer identity, import reports, and
  Inbox drop targets. Selection rules are in
  [photo-selection.md](photo-selection.md).
- Keep a long album list manageable. Album rows are 30px tall. Each row has
  one actions button in place of four. From eight albums up, a Filter albums
  field sits under My Albums and lists matching albums and folders from every
  folder, flat, with the folder path as the tooltip.
- Settings > Library shows the vault's size on disk.
- The video player hides AirPlay unless Settings > General > Show AirPlay in
  the video player is on. It is off by default.

## Implementation

`ui/index.html` owns the semantic CSS color tokens, light/dark media queries,
responsive toolbar, shared SVG symbol definitions, sidebar, and existing
screens. `icon` reuses the symbols across the toolbar, sidebar, and viewer.
`renderSidebar` builds navigation buttons and separate album tools. The
*My Albums* heading toggles the album list; `pv-albums-collapsed` saves it.
The `albums` view hides photo sorting, layout, and selection controls, and
`renderAlbumCards` shows one card per album, matching the search, with its
newest photo as the cover. Album names in the sidebar, cards, selection menu,
and view title carry a `title` tooltip with the full name.
`loadGrid` and other refreshes of the same view call
`renderPhotos({ keepScroll: true })`. It rebuilds as many items as were
showing, reuses loaded thumbnails, and restores the window and list scroll
offsets, so filing photos into an album or an Inbox batch doesn't jump to the
top. Switching views still starts at the first batch.
`renderPhotos` updates the view title/count and renders a scrollable list.
`libraryCounts` makes one pass over `photos` (about 4ms for 30,000 items and
500 albums) for the library, album, and smart album counts, then walks each
album's folder chain for folder counts. `renderSidebar` calls it, so every
caller that refreshes the sidebar refreshes the counts.
The accent fills the active sidebar row and primary buttons. `--on-accent`
holds the text color that sits on it.
When the grid is sorted by date, `renderYearRail` lists years down the right
edge behind a thin left border. `updateRailYear` highlights the year whose
month heading has reached the top of the view (`.on` and `aria-current`).
A window scroll listener runs it at most once per animation frame. A rail
jump renders one batch past the target so the page is tall enough to put
that year at the top.
`setHeaderHeight` measures the toolbar to size the list's scroll area.
`--sbw` controls the sidebar boundary, content inset, and file-drop overlay.
The `#sbresize` handle sets it by drag or arrow keys, between 170px and the
smaller of 480px or half the window. The width is saved in `pv-sidebar-width`
and double-click clears it.
The document keyboard handler guards focused controls and contains Tab focus
within modal presentations. Command-F focuses search.

Backend commands, vault formats, and native window configuration are unchanged.
Sorting and ingestion contracts remain documented in their existing flow records.

## Verification

Baseline: commit `0deab25` plus existing uncommitted sorting and ingestion work.
Before-task files and logs are in `/tmp/photovault-macos-redesign/`.

- PASS baseline: `node --test tests/*.test.cjs`, 37 tests.
- PASS final frontend suite: 40 tests. Three added checks cover control
  activation, viewer arrow navigation, and focus restoration. The existing
  favorite-state assertion now checks `aria-pressed` instead of a glyph.
- PASS browser: light/dark layouts, 600 by 400 grid toolbar, horizontal list
  scrolling with a 224px name column, sticky list headers, sidebar keyboard
  activation/focus, viewer arrows, dialog focus/return, forward and reverse
  Tab from the viewer root, Command-F search, album drop hit testing, and
  clearing the new title/count on lock. No JavaScript errors in these checks.
- PASS: `npm run build` after the final UI change. Bundle:
  `src-tauri/target/release/bundle/macos/PhotoVault.app`. The existing unused
  `derive_key` warning remains.
- PASS: independent targeted review. Viewer button navigation and reverse
  Tab from the dialog root were corrected and checked again.
- PASS: `git diff --check`. Backend tests were not rerun for this UI-only change.

The task-only UI/README diffs, test logs, build log, and `browser-evidence.json`
are in `/tmp/photovault-macos-redesign/`. Checks used Node v22.23.2 on macOS.
The light appearance screenshot is
`/Users/nikhlkapadia/.t3/userdata/browser-artifacts/browser-screenshot-localhost-mtufsk9v-d8a38e3e.png`.

Nocturne restyle, 2026-11-09:

- PASS: `node --test tests/*.test.cjs`, 126 tests. `tests/library-view.test.cjs`
  adds three: one-pass counts including nested folder totals, rail
  highlighting while scrolling, and the rail ignoring years not yet rendered.
- PASS browser: headless Chromium at 1440 by 900 with a stubbed Tauri API and
  generated images. Checked dark and light grids, list and Albums views, the
  focus ring on the active sidebar row, increased contrast with reduced
  transparency, and rail highlighting after jumps and scrolls with 1,777 and
  30,000 items. No JavaScript errors.
- Not run: `npm run build` and the native app.

AirPlay option, 2026-11-13:

`Settings.airplay` in `src-tauri/src/main.rs` defaults to false, including
for settings files saved before it existed. `applyAirplay` in `ui/index.html`
sets `x-webkit-airplay` and `disableRemotePlayback` on `#lbvid` at unlock and
on every settings change. The markup starts as `deny`, so a failed settings
load stays hidden.

- PASS: `node --test tests/*.test.cjs`, 134 tests, one new for this option.
- PASS: `cargo test`, 125 tests, one new
  (`airplay_is_off_unless_settings_turn_it_on`).
- NOT RUN: the native app. Nobody has confirmed that the button leaves the
  WKWebView video controls, or that it comes back, with an AirPlay receiver
  on the network.

Sidebar and vault size, 2026-11-13:

`renderSidebar` builds the fixed rows and calls `albumRows` for My Albums and
`wireSidebarRows` for the handlers. Typing in `#albfilter` redraws only
`#albumlist`, so the field keeps its focus. A full sidebar refresh restores
the focus and caret. `albumFilter` resets on lock and when the list drops
under `ALBUM_FILTER_MIN`.

`vault_size` in `src-tauri/src/main.rs` adds the sizes of the files in the
vault folder and its `objects` folder. It needs an unlocked vault and releases
the vault lock before reading the disk. Settings shows "Calculating…" until it
answers and "Unavailable" if it fails.

- PASS: `node --test tests/*.test.cjs`, 140 tests, two new for these.
- PASS: `cargo test`, 126 tests, one new
  (`vault_size_adds_up_objects_and_vault_files`).
- PASS: headless WebKit with 32 synthetic albums. Typing filtered the list
  and kept focus, Escape cleared it, and Settings showed the stubbed size.
- NOT RUN: the native app, and `vault_size` against a real vault.

Browser fixtures use sample images stored outside the repository. They are
preview data only. No personal vault or Inbox is used. Native VoiceOver,
macOS accessibility-preference propagation, and native app launch are not
verified by the browser checks.
