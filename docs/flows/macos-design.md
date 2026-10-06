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
- Keep toolbar actions, search, albums, and sorting usable at 1100 by 760 and
  the minimum 600 by 400 window size. A narrow list scrolls horizontally so
  names and sortable columns retain their width.
- Keep the selected library or album title and count current. Clear them on lock.
- Support keyboard sidebar navigation and visible focus. Control activation
  must not also invoke photo shortcuts. Keep focus within an open dialog.
- Preserve column sorting, selection, viewer identity, import reports, and
  Inbox drop targets.

## Implementation

`ui/index.html` owns the semantic CSS color tokens, light/dark media queries,
responsive toolbar, shared SVG symbol definitions, sidebar, and existing
screens. `icon` reuses the symbols across the toolbar, sidebar, and viewer.
`renderSidebar` builds navigation buttons and separate album tools.
`renderPhotos` updates the view title/count and renders a scrollable list.
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

Browser fixtures use sample images stored outside the repository. They are
preview data only. No personal vault or Inbox is used. Native VoiceOver,
macOS accessibility-preference propagation, and native app launch are not
verified by the browser checks.
