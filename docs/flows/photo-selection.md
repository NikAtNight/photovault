# Photo selection and filing

## Requirement and ownership

On 2026-11-13 the user reported three problems in the Mac app: Shift-click
did not select a range, changing views dropped the selection, and the Album
menu had no search and no way to create the album you were looking for.
Owner: PhotoVault maintainers.

On the same day the user asked for three follow-ups: drag photos onto sidebar
albums, right-click menus, and a message after filing.

Not covered: Shift with the arrow keys, drag selection, and album cards in
the Albums view, which keep their own `cardSelection`.

## Intended behavior

- Shift-click selects every photo between the last clicked photo and this
  one. It works with select mode on or off. With no earlier click in the
  view, it selects the one photo instead of opening it. The anchor stays put,
  so a second Shift-click can reach the other way.
- Command-click and Space on the focused photo set the anchor too.
- The selection and select mode carry across sidebar views, album cards, and
  searches. Example: pick two photos in All Photos, open an album, pick one
  more, and the bar reads "3 selected · 2 not in this view".
- Entering or leaving Recently Deleted clears the selection. Its bar offers
  Delete Forever, which must never reach a photo picked in a live view.
- Every bar action applies to the whole selection, including photos outside
  the open view.
- The Album menu opens with a search field focused. Typing filters albums by
  name. A name no album has adds a "Create album" row. Enter takes the first
  row, so it picks the best match or creates the album when nothing matches.
  Down Arrow moves into the list. Escape closes the menu and keeps the
  selection.

- Dragging a photo onto a sidebar album adds it there. A selected photo
  carries the whole selection. Any other photo goes alone and leaves the
  selection as it was. A pill by the pointer names the target, such as
  "Add 3 items to “Trip”". Escape, or a release anywhere else, files
  nothing. The selection stays after a drop. Recently Deleted photos don't
  drag.
- Filing by drag or by the Album menu shows a toast with Undo, such as
  "Added 2 items to “Trip” · 1 already there". Undo reverses only what that
  action changed. Undoing a new album deletes the album. With nothing to
  change the toast says "Already in “Trip”" and offers no Undo.
- A right-click on a photo opens a menu of the selection bar's actions. As in
  Finder, a photo outside the selection replaces it first. Recently Deleted
  offers only Restore and Delete Forever.
- A right-click on a sidebar album, folder, or smart album, or on an album
  card, opens Rename or Edit, Move to Folder, Share to iPhone, and Delete,
  whichever apply. The row's one button opens the same menu.
- Escape closes an open menu first. A second press clears the selection.

## Implementation

All of it is in `ui/index.html`.

`tileClick` checks Shift before select mode. `lastClick` is the anchor, an
index into `visible`. `openView`, the search field, and `saveSort` reset it,
because each one changes what that index points at.

`openView` no longer calls `clearSelection` unless the view change crosses
Recently Deleted. It always clears `cardSelection`.

`updateSelectionUI` counts selected ids missing from `visible` for the "not
in this view" note. `selshare` sorts the whole selection with `sortPhotos`.
In the Duplicates view that order differs from the grid, which groups by
file contents.

`renderAlbumMenu` builds the rows in `#albumrows` under the `#albumsearch`
field. `fileSelection` runs the chosen row: `album_create` then
`albums_assign` for a new album, or `albums_assign` alone. A failed call
shows the error and keeps the selection. New albums go to the top level.
`clearVaultUI` closes the menu and wipes the typed text and album names.

`filePhotos` saves one album change, works out which photos it changed, and
shows the toast. `fileSelection` and the drag both call it. A failed save
shows the error and no Undo. Undo does nothing after the vault locks.

The app blocks native drags so Finder imports don't misfire, so `armPhotoDrag`
and document `pointermove` and `pointerup` handlers carry the drag. It starts
after 6px of movement. `photoDragOver` finds the album row under the pointer
and reuses `autoScrollSidebar`. `tileClick` ignores a click within 100ms of a
drag ending. `clearVaultUI` ends a drag in flight. A closed sidebar folder
does not spring open under a drag, so open it first.

`openMenu` fills `#ctxmenu` from `ctxItems` and `placeMenu` keeps it inside
the window. `photoMenu` and `itemMenu` build the rows. `#albummenu` now sits
at the top level of the page so `openAlbumMenu` can put it above the Album
button or at the pointer.

## Verification

Checked on commit `a654f81` plus uncommitted changes, macOS, Node v22.23.2.

- PASS: `node --test tests/*.test.cjs`, 134 tests. Eight are new, at the end
  of `tests/ingestion.test.cjs`. Six cover this flow: Shift ranges, selection
  across views, the Recently Deleted boundary, sharing photos outside the
  view, album menu filtering and escaping, and filing with create, add,
  remove, cancel, and a failed create. One checks that no element id repeats.
- PASS: five of those six fail against the previous `ui/index.html`. The
  Recently Deleted case passed before too, since every view change cleared
  the selection.
- PASS: headless WebKit (Playwright build 2359) at 1100 by 760, loading
  `ui/index.html` with a stubbed Tauri API and 32 synthetic albums. Covered
  the menu opening with the field focused, typing and filtering, the Create
  row, Down Arrow, Enter creating an album, clicking a match, Escape, a
  Shift range in select mode, Shift with no earlier click, and the selection
  surviving a view change. No JavaScript errors.
- NOT RUN: these steps in the native app.

Follow-ups, same day:

- PASS: `node --test tests/*.test.cjs`, 140 tests. Four more cover this
  flow: filing toasts and Undo, Undo of a new album with failed and locked
  cases, dragging to an album with every way of not filing, and right-click
  menus per view. All four fail against the previous `ui/index.html`.
- PASS: headless WebKit, same setup. Covered dragging one tile and a
  selection of three onto sidebar albums, the pill text, Undo from the toast,
  a drag released over the grid, a plain click still opening the viewer,
  right-click menus on a tile, sidebar rows, and an album card, Add to Album
  from the menu, a menu at the window's corner staying inside it, and Escape
  closing the menu before the selection. No JavaScript errors.
- NOT RUN: these steps in the native app. WKWebView inside Tauri may treat
  pointer events during a drag, or Control-click, differently from the
  Playwright WebKit build.

The first build of this menu reused the sidebar's `albumlist` id. The rows
drew in the sidebar and the menu showed only its search field. The in-memory
DOM could not see that, which is why the id test and the WebKit check exist.
