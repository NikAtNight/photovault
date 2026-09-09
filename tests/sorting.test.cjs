const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');

// Exercise the shipped inline functions without opening or unlocking a vault.
process.env.TZ = 'America/Toronto';
const html = readFileSync(require('node:path').join(__dirname, '../ui/index.html'), 'utf8');
const sorting = html.slice(html.indexOf('const sortColumns ='), html.indexOf('function computeVisible()'));
const filtering = html.slice(html.indexOf('function computeVisible()'), html.indexOf('function emptyMessage()'));
function app(saved = {}) {
  const storage = new Map(Object.entries(saved));
  const ctx = vm.createContext({
    localStorage: { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) },
    ext: name => name.split('.').pop().toUpperCase(),
    renderPhotos() {}, toast() {},
    lastClick: 4, focusIdx: 4,
    photos: [], currentView: { type: 'all' }, query: '', isVideo: p => /\.(mov|mp4)$/i.test(p.name),
  });
  vm.runInContext(sorting + filtering, ctx);
  return {
    ctx, storage,
    run: code => vm.runInContext(code, ctx),
    sort(list, rules) {
      ctx.input = list;
      if (rules) ctx.config = { rules };
      if (rules) vm.runInContext('photoSort = config', ctx);
      vm.runInContext('sortPhotos(input)', ctx);
      return Array.from(ctx.input, p => p.id);
    },
  };
}
const photo = (id, name, added, extra = {}) => ({ id, name, added: new Date(added).getTime() / 1000, albums: [], ...extra });
const sample = () => [
  photo('old', 'House_1.jpg', '2026-09-08T12:00:00-04:00'),
  photo('ten', 'House_10.jpg', '2026-09-09T08:00:00-04:00'),
  photo('two', 'House_2.jpg', '2026-09-09T23:00:00-04:00'),
  photo('one', 'House_1.jpg', '2026-09-09T15:00:00-04:00'),
];

test('defaults to newest calendar day, then numeric-aware names regardless of upload time', () => {
  assert.deepEqual(app().sort(sample()), ['one', 'two', 'ten', 'old']);
});
test('each column has an independent direction', () => {
  assert.deepEqual(app().sort(sample(), [{ key: 'added', dir: 'asc' }, { key: 'name', dir: 'desc' }]),
    ['old', 'ten', 'two', 'one']);
});
test('sorting by date alone uses exact timestamps', () => {
  assert.deepEqual(app().sort(sample(), [{ key: 'added', dir: 'desc' }]), ['two', 'one', 'ten', 'old']);
});
test('day boundaries use local dates rather than UTC dates', () => {
  const list = [photo('late', 'Z.jpg', '2026-09-09T23:50:00-04:00'),
    photo('early', 'A.jpg', '2026-09-09T00:10:00-04:00'),
    photo('next', 'B.jpg', '2026-09-10T00:10:00-04:00')];
  assert.deepEqual(app().sort(list), ['next', 'early', 'late']);
});
test('both repeated times at the DST boundary belong to the same day', () => {
  const list = [photo('z', 'Z.jpg', '2026-11-01T01:30:00-05:00'),
    photo('a', 'A.jpg', '2026-11-01T01:30:00-04:00')];
  assert.deepEqual(app().sort(list), ['a', 'z']);
});
test('date taken falls back to date added when EXIF is absent', () => {
  const list = sample();
  list[0].taken = new Date('2026-09-10T12:00:00-04:00').getTime() / 1000;
  assert.deepEqual(app().sort(list, [{ key: 'taken', dir: 'desc' }, { key: 'name', dir: 'asc' }]),
    ['old', 'one', 'two', 'ten']);
});
test('three columns resolve ties in their specified priority', () => {
  const list = sample();
  list[1].size = 100;
  list[2].size = 100;
  list[3].size = 10;
  assert.deepEqual(app().sort(list, [{ key: 'added', dir: 'desc' }, { key: 'size', dir: 'desc' }, { key: 'name', dir: 'asc' }]),
    ['two', 'ten', 'one', 'old']);
});
test('type sorting supports descending direction', () => {
  const list = [photo('jpg', 'A.jpg', '2026-09-09'), photo('png', 'A.png', '2026-09-09')];
  assert.deepEqual(app().sort(list, [{ key: 'type', dir: 'desc' }]), ['png', 'jpg']);
});
test('identical sort values have a stable order independent of input order', () => {
  const list = [photo('b', 'House.jpg', '2026-09-09'), photo('a', 'house.jpg', '2026-09-09')];
  assert.deepEqual(app().sort(list), ['a', 'b']);
  assert.deepEqual(app().sort(list.reverse()), ['a', 'b']);
});
test('saved multi-column sort survives reload', () => {
  const first = app();
  first.run("setSort('size', true)");
  const second = app(Object.fromEntries(first.storage));
  assert.equal(second.run('JSON.stringify(photoSort)'), first.run('JSON.stringify(photoSort)'));
});
test('legacy date direction is preserved and name sorting is added', () => {
  const a = app({ 'pv-sort': 'added-asc' });
  assert.deepEqual(a.sort(sample()), ['old', 'one', 'two', 'ten']);
  assert.equal(app({ 'pv-sort': 'type-desc' }).run('photoSort.rules[0].dir'), 'desc');
});
test('malformed or invalid preferences recover to a valid default', () => {
  for (const value of ['{broken', 'null', '{}', '{"byDay":true,"rules":[]}',
    JSON.stringify({ byDay: true, rules: [{ key: 'constructor', dir: 'asc' }] }),
    JSON.stringify({ byDay: true, rules: [{ key: 'name', dir: 'asc' }, { key: 'name', dir: 'asc' }] }),
    JSON.stringify({ byDay: true, rules: [{ key: 'size', dir: 'sideways' }] })]) {
    assert.deepEqual(app({ 'pv-sort-rules': value }).sort(sample()), ['one', 'two', 'ten', 'old']);
  }
});
test('plain click resets to one column, while Shift-click adds or reverses it', () => {
  const a = app();
  a.run("setSort('size', true); setSort('size', true)");
  assert.equal(a.run('photoSort.rules[2].dir'), 'asc');
  a.run("setSort('name')");
  assert.equal(a.run("photoSort.rules.map(r => r.key).join(',')"), 'name');
  assert.equal(a.ctx.lastClick, -1);
  assert.equal(a.ctx.focusIdx, -1);
});
test('click date then Shift-click name sorts names within each local day', () => {
  const a = app({ 'pv-sort': 'name-asc' });
  a.run("setSort('added'); setSort('name', true)");
  assert.deepEqual(a.sort(sample()), ['one', 'two', 'ten', 'old']);
  a.run("setSort('name', true)");
  assert.deepEqual(a.sort(sample()), ['ten', 'two', 'one', 'old']);
  a.run("setSort('added')");
  assert.equal(a.run('photoSort.rules.length'), 1);
  assert.deepEqual(a.sort(sample()), ['old', 'ten', 'one', 'two']);
});
test('grid dropdown uses its explicit direction', () => {
  const a = app();
  a.run("setSort('added', false, 'desc')");
  assert.deepEqual(a.sort(sample()), ['two', 'one', 'ten', 'old']);
});
test('search, albums and favorites retain the chosen sort order', () => {
  const a = app();
  a.ctx.photos = sample().map(p => ({ ...p, favorite: p.id !== 'ten', albums: ['album1'] }));
  for (const view of [{ type: 'all' }, { type: 'album', album: 'album1' }, { type: 'favorites' }]) {
    a.ctx.currentView = view;
    a.ctx.query = 'house';
    assert.deepEqual(Array.from(a.run('computeVisible()'), p => p.id),
      view.type === 'favorites' ? ['one', 'two', 'old'] : ['one', 'two', 'ten', 'old']);
  }
});
test('duplicates remain adjacent under the existing content grouping', () => {
  const a = app();
  a.ctx.photos = sample().map((p, i) => ({ ...p, hash: i % 2 ? 'hashB' : 'hashA' }));
  a.ctx.currentView = { type: 'duplicates' };
  assert.deepEqual(Array.from(a.run('computeVisible()'), p => p.hash), ['hashA', 'hashA', 'hashB', 'hashB']);
});
test('the full inline application script parses', () => {
  new vm.Script(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
});
