const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');

// Exercise the shipped sidebar counts and year rail without a DOM or a vault.
const html = readFileSync(require('node:path').join(__dirname, '../ui/index.html'), 'utf8');
const slice = (from, to) => html.slice(html.indexOf(from), html.indexOf(to));
const filtering = slice('function matchesQuery(', 'function emptyMessage()');
const library = slice('const folderOf =', 'function renderSidebar()');
const rail = slice('let railYears =', 'function jumpTo(');

function counts({ photos, albums = [], folders = [], smartAlbums = [] }) {
  const ctx = vm.createContext({
    photos, albums, folders, smartAlbums, folderById: new Map(folders.map(f => [f.id, f])),
    isVideo: p => /\.(mov|mp4)$/i.test(p.name),
  });
  vm.runInContext(filtering + library, ctx);
  return vm.runInContext('libraryCounts()', ctx);
}

test('library counts cover every sidebar row in one pass and leave deleted items to Recently Deleted', () => {
  const photo = (id, extra = {}) => ({ id, name: `${id}.jpg`, added: 1, albums: [], ...extra });
  const c = counts({
    photos: [
      photo('a', { favorite: true, albums: ['trip'], hash: 'x' }),
      photo('b', { hash: 'x' }),
      photo('c', { name: 'c.mov', albums: ['trip', 'pets'] }),
      photo('d', { deleted: 5, favorite: true, albums: ['trip'], hash: 'x' }),
    ],
    albums: [{ id: 'trip', folder: 'y26' }, { id: 'pets', folder: 'home' }, { id: 'loose', folder: null }, { id: 'lost', folder: 'gone' }],
    folders: [{ id: 'travel', parent: null }, { id: 'y26', parent: 'travel' }, { id: 'home', parent: null }, { id: 'empty', parent: null }],
    smartAlbums: [{ id: 'faves', rules: { favorite: true } }, { id: 'clips', rules: { kind: 'video' } }, { id: 'none', rules: { query: 'zzz' } }],
  });
  assert.deepEqual({ all: c.all, favorites: c.favorites, videos: c.videos, unfiled: c.unfiled, duplicates: c.duplicates, trash: c.trash },
    { all: 3, favorites: 1, videos: 1, unfiled: 1, duplicates: 2, trash: 1 });
  assert.deepEqual(Object.fromEntries(c.albums), { trip: 2, pets: 1 });
  assert.deepEqual(Object.fromEntries(c.smart), { faves: 1, clips: 1, none: 0 });
  // A folder counts the albums anywhere inside it. An album whose folder is gone counts nowhere.
  assert.deepEqual(Object.fromEntries(c.folders), { y26: 1, travel: 1, home: 1 });
});

class Button {
  constructor(year) { this.textContent = String(year); this.classes = new Set(); this.attrs = {};
    this.classList = { toggle: (n, on) => on ? this.classes.add(n) : this.classes.delete(n) }; }
  setAttribute(name, value) { this.attrs[name] = value; }
}
// Items are one per year, each with a month heading above it at `tops[year]`.
function yearRail(years) {
  const buttons = [], tiles = new Map();
  const railEl = { hidden: true, set innerHTML(v) { buttons.length = 0; for (const m of v.matchAll(/>(\d+)</g)) buttons.push(new Button(m[1])); },
    querySelectorAll: () => buttons };
  const elements = { yearrail: railEl, content: { classList: { add() {}, remove() {} } } };
  const visible = years.map(y => ({ id: String(y), added: new Date(y, 5, 1).getTime() / 1000 }));
  const tops = {};
  for (const p of visible) {
    const heading = { classList: { contains: n => n === 'ghead' }, getBoundingClientRect: () => ({ top: tops[p.id] }) };
    tiles.set(p.id, { previousElementSibling: heading, getBoundingClientRect: () => ({ top: tops[p.id] + 40 }) });
  }
  let onScroll = null;
  const frames = [];
  const ctx = vm.createContext({
    $: id => elements[id], visible, tileById: tiles, layout: 'grid', currentView: { type: 'all' },
    photoSort: { rules: [{ key: 'added', dir: 'desc' }] },
    document: { querySelector: () => ({ offsetHeight: 80 }) },
    window: { addEventListener: (name, fn) => { if (name === 'scroll') onScroll = fn; } },
    requestAnimationFrame: fn => frames.push(fn),
  });
  vm.runInContext(rail, ctx);
  return {
    tops, buttons, tiles,
    render: () => vm.runInContext('renderYearRail()', ctx),
    // Two scroll events in one frame update the rail once.
    scroll: () => { onScroll(); onScroll(); assert.equal(frames.length, 1); frames.shift()(); },
    active: () => buttons.filter(b => b.classes.has('on')).map(b => b.textContent + (b.attrs['aria-current'] === 'true' ? '!' : '')),
  };
}

test('the year rail highlights the year at the top of the view as the grid scrolls', () => {
  const r = yearRail([2026, 2025, 2024]);
  Object.assign(r.tops, { 2026: 100, 2025: 900, 2024: 1700 });
  r.render();
  assert.deepEqual(r.active(), ['2026!']);
  assert.equal(r.buttons[1].attrs['aria-current'], 'false');
  // A jump puts the month heading just under the 80px toolbar.
  Object.assign(r.tops, { 2026: -1500, 2025: 88, 2024: 900 });
  r.scroll();
  assert.deepEqual(r.active(), ['2025!']);
  Object.assign(r.tops, { 2026: -3000, 2025: -1500, 2024: 50 });
  r.scroll();
  assert.deepEqual(r.active(), ['2024!']);
  Object.assign(r.tops, { 2026: 100, 2025: 900, 2024: 1700 });
  r.scroll();
  assert.deepEqual(r.active(), ['2026!']);
});

test('the rail stops at the first year whose items are not rendered yet', () => {
  const r = yearRail([2026, 2025, 2024]);
  Object.assign(r.tops, { 2026: -3000, 2025: -1500, 2024: 50 });
  r.tiles.delete('2025');
  r.render();
  assert.deepEqual(r.active(), ['2026!']);
});
