const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');

// Run the shipped app script with an in-memory DOM and Tauri boundary.
// No native app, filesystem commands, or real vault data are used.
const html = readFileSync(require('node:path').join(__dirname, '../ui/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1].replace(/refresh\(\);\s*$/, '');
class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.style = { setProperty() {} };
    this.dataset = {};
    this.children = [];
    this.events = {};
    this.value = '';
    this._text = '';
    this._html = '';
    this.pauseCount = 0;
    this.loadCount = 0;
    const classes = new Set();
    this.classList = {
      add: (...names) => names.forEach(n => classes.add(n)),
      remove: (...names) => names.forEach(n => classes.delete(n)),
      contains: n => classes.has(n),
      toggle(n, force = !classes.has(n)) { force ? classes.add(n) : classes.delete(n); },
    };
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(' '); }
  set innerHTML(value) { this._html = value; this._text = ''; this.children = []; }
  get innerHTML() { return this._html; }
  appendChild(child) { this.children.push(child); return child; }
  prepend(child) { this.children.unshift(child); }
  get lastElementChild() { return this.children.at(-1); }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  replaceChildren(...children) { this.children = children; this._text = ''; this._html = ''; }
  insertBefore(child) { return this.appendChild(child); }
  querySelector() { return new Element(); }
  querySelectorAll() { return []; }
  addEventListener(name, fn) { this.events[name] = fn; }
  removeAttribute(name) { delete this[name]; }
  setAttribute(name, value) { this[name] = value; }
  insertAdjacentHTML() {}
  getBoundingClientRect() { return { width: 1000, height: 800, top: 0, left: 0 }; }
  pause() { this.pauseCount++; }
  load() { this.loadCount++; }
  focus() { this.focusCount = (this.focusCount || 0) + 1; }
  select() {}
  remove() {}
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const photo = (id, name = `${id}.jpg`) => ({ id, name, added: 1000, albums: [], favorite: false });
const result = extra => ({ imported: 0, skipped: 0, failed: 0, cleanup_failed: 0, issues: [], ...extra });
function app() {
  const elements = new Map(), listeners = new Map(), calls = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  // Timers never fire on their own; tests run a recorded callback to drive it.
  const state = { photos: [], handlers: {}, timers: [], save: async () => '/export', open: async () => null, ask: async () => true };
  const observer = class { observe() {} unobserve() {} disconnect() {} };
  const ctx = vm.createContext({
    document: { getElementById: element, createElement: tag => new Element(tag),
      createDocumentFragment: () => new Element(), querySelector: element,
      querySelectorAll: () => [], addEventListener: (name, handler) => listeners.set(`dom:${name}`, handler), documentElement: new Element() },
    window: { addEventListener() {}, __TAURI__: {
      core: { invoke: async (command, args) => {
        calls.push({ command, args });
        if (state.handlers[command]) return state.handlers[command](args);
        if (command === 'list_photos') return structuredClone(state.photos);
        if (command === 'list_albums') return [];
        if (command === 'vault_status') return 'locked';
        if (command === 'trash_photos') state.photos = state.photos.map(p => args.ids.includes(p.id) ? { ...p, deleted: true } : p);
        return null;
      } },
      dialog: { save: args => state.save(args), ask: (...args) => state.ask(...args), open: args => state.open(args) },
      event: { listen: (name, handler) => listeners.set(name, handler) },
    } },
    localStorage: { getItem: () => null, setItem() {} },
    ResizeObserver: observer, IntersectionObserver: observer,
    setTimeout: (fn, ms) => state.timers.push({ fn, ms }), clearTimeout() {}, setInterval: () => 1, clearInterval() {},
    cancelAnimationFrame() {}, requestAnimationFrame: () => 1,
  });
  vm.runInContext(script, ctx);
  element('gallery').style.display = 'block';
  return { state, calls, element, run: code => vm.runInContext(code, ctx),
    emit: (name, payload) => listeners.get(name)({ payload }),
    keydown: event => listeners.get("dom:keydown")({ preventDefault() {}, ...event }),
    async seed(list) { state.photos = list; await vm.runInContext('loadGrid()', ctx); },
  };
}

test('background insertion preserves viewer identity, zoom, and favorite/delete targets', async () => {
  const a = app();
  await a.seed([photo('b'), photo('c')]);
  await a.run('show(0); zoom.s = 3');
  await a.seed([photo('a'), photo('b'), photo('c')]);
  assert.equal(a.run('cur'), 1);
  assert.equal(a.run('viewerId'), 'b');
  assert.equal(a.run('zoom.s'), 3);
  assert.match(a.element('lbimg').src, /\/b$/);
  await a.element('lbfav').onclick();
  assert.deepEqual(Array.from(a.calls.find(c => c.command === 'set_favorite').args.ids), ['b']);
  await a.element('lbdel').onclick();
  assert.deepEqual(Array.from(a.calls.find(c => c.command === 'trash_photos').args.ids), ['b']);
  assert.equal(a.run('viewerId'), 'c');
  assert.match(a.element('lbimg').src, /\/c$/);
  await a.element('lbfav').onclick();
  assert.deepEqual(Array.from(a.calls.filter(c => c.command === 'set_favorite').at(-1).args.ids), ['c']);
});

test('a refresh leaves video playback intact when the open item survives', async () => {
  const a = app();
  await a.seed([photo('b', 'b.mov')]);
  await a.run('show(0)');
  const vid = a.element('lbvid'), paused = vid.pauseCount, loaded = vid.loadCount;
  vid.currentTime = 42;
  await a.seed([photo('a'), photo('b', 'b.mov')]);
  assert.equal(a.run('cur'), 1);
  assert.equal(vid.pauseCount, paused);
  assert.equal(vid.loadCount, loaded);
  assert.equal(vid.currentTime, 42);
  assert.match(vid.src, /\/b$/);
});

test('export stays bound to the photo chosen before its save dialog', async () => {
  const a = app(), dialog = deferred();
  await a.seed([photo('b'), photo('c')]);
  await a.run('show(0)');
  a.state.save = () => dialog.promise;
  const exporting = a.element('lbexport').onclick();
  await a.seed([photo('a'), photo('b'), photo('c')]);
  await a.run('show(2)');
  dialog.resolve('/chosen');
  await exporting;
  assert.equal(a.calls.find(c => c.command === 'export_photo').args.id, 'b');
  assert.equal(a.element('toastmsg').textContent, 'Exported b.jpg');
});

test('mixed and all-failed imports remain reviewable with safely rendered issues', async () => {
  const a = app();
  const filename = '<img src=x onerror=alert(1)>.jpg';
  a.state.handlers.import_photos = async () => result({ imported: 2, failed: 1, cleanup_failed: 1,
    issues: [{ name: filename, reason: 'Cannot decode <contents>', stage: 'import' },
      { name: 'retained.jpg', reason: 'Preserved in recovery/retained.jpg', stage: 'cleanup' }] });
  await a.run('importPaths(["/mock/file"])');
  assert.equal(a.element('importresults').hidden, false);
  const first = a.element('importreports').children[0];
  assert.match(first.textContent, /2 imported.*1 failed.*1 cleanup failure/);
  assert.match(first.textContent, /Preserved in recovery\/retained.jpg/);
  assert.equal(first.children[1].children[0].innerHTML, '');
  assert.match(first.children[1].children[0].textContent, /<img src=x onerror=alert\(1\)>/);
  a.state.handlers.import_photos = async () => result({ failed: 3 });
  await a.run('importPaths(["/mock/file"])');
  assert.equal(a.element('importreports').children.length, 2);
  assert.match(a.element('importreports').children[0].textContent, /0 imported.*3 failed/);
  assert.doesNotMatch(a.element('toastmsg').textContent, /No new media/);
  a.element('clearimportresults').onclick();
  assert.equal(a.element('importreports').children.length, 0);
  assert.equal(a.element('importresults').hidden, true);
});

for (const fails of [false, true]) {
  test(`Inbox event during manual processing refreshes after ${fails ? 'rejection' : 'completion'}`, async () => {
    const a = app(), manual = deferred();
    a.state.handlers.process_inbox = () => manual.promise;
    const processing = a.element('inboxbtn').onclick();
    a.state.photos = [photo('arrived')];
    await a.emit('inbox-imported', result({ imported: 1 }));
    assert.equal(a.calls.filter(c => c.command === 'list_photos').length, 0);
    if (fails) manual.reject(new Error('disk unavailable'));
    else manual.resolve(result());
    await processing;
    assert.equal(a.run('photos[0].id'), 'arrived');
    assert.equal(a.run('pendingImportRefresh'), false);
    assert.equal(a.run('importing'), false);
    assert.equal(a.element('importreports').children.length, 2);
    if (fails) assert.match(a.element('importreports').textContent, /disk unavailable/);
  });
}

test('failure-only background events show the filename and retry reason', async () => {
  const a = app();
  await a.emit('inbox-imported', result({ failed: 1, issues: [
    { name: 'house.jpg', reason: 'No space left', stage: 'import', retryable: true },
  ] }));
  assert.match(a.element('importreports').textContent, /house.jpg: No space left.*Can be retried/);
});

test('Inbox events reload albums so zip albums appear in the sidebar', async () => {
  const a = app();
  a.state.handlers.list_albums = () => [{ id: 'trip', name: 'Trip', created: 1 }];
  a.state.photos = [{ ...photo('arrived'), albums: ['trip'] }];
  await a.emit('inbox-imported', result({ imported: 1 }));
  assert.equal(a.run('albums[0].name'), 'Trip');
  assert.equal(a.run('photos[0].albums[0]'), 'trip');
});

test('Inbox progress updates the toast without refreshing the library', async () => {
  const a = app();
  await a.emit('inbox-progress', { done: 0, total: 0 });
  assert.equal(a.element('toastmsg').textContent, 'Unzipping Inbox archive…');
  await a.emit('inbox-progress', { done: 25, total: 300 });
  assert.equal(a.element('toastmsg').textContent, 'Importing from Inbox 25 / 300…');
  assert.equal(a.calls.some(c => c.command === 'list_photos' || c.command === 'list_albums'), false);
});

test('library-changed shows saved photos and albums before the pass ends', async () => {
  const a = app();
  a.state.handlers.list_albums = () => [{ id: 'trip', name: 'Trip', created: 1 }];
  a.state.photos = [{ ...photo('arrived'), albums: ['trip'] }];
  await a.emit('library-changed', null);
  assert.equal(a.run('albums[0].name'), 'Trip');
  assert.equal(a.run('photos[0].albums[0]'), 'trip');
  assert.equal(a.run('pendingImportRefresh'), false);
});

test('library-changed waits while a manual import is running', async () => {
  const a = app();
  a.run('importing = true');
  await a.emit('library-changed', null);
  assert.equal(a.calls.some(c => c.command === 'list_photos'), false);
});

test('a failed library refresh retries with backoff and reports once per streak', async () => {
  const a = app();
  let failures = 2;
  a.state.handlers.list_photos = () => {
    if (failures-- > 0) throw new Error('index busy');
    return [photo('arrived')];
  };
  const retry = () => a.state.timers[a.run('refreshRetry') - 1];
  await a.emit('library-changed', null);
  assert.equal(a.element('importreports').children.length, 1);
  assert.match(a.element('importreports').textContent, /Library refresh.*index busy/);
  assert.equal(a.run('pendingImportRefresh'), true);
  assert.equal(retry().ms, 1000);
  // Another event during the streak tries right away but adds no second timer.
  const scheduled = a.run('refreshRetry');
  await a.emit('library-changed', null);
  assert.equal(a.run('refreshRetry'), scheduled);
  assert.equal(a.run('refreshBackoff'), 2000);
  assert.equal(a.element('importreports').children.length, 1);
  retry().fn();
  await new Promise(setImmediate);
  assert.equal(a.run('photos[0].id'), 'arrived');
  assert.equal(a.run('pendingImportRefresh'), false);
  assert.equal(a.run('refreshRetry'), null);
  assert.equal(a.run('refreshBackoff'), 0);
  assert.equal(a.element('importreports').children.length, 1);
});

test('a failed album load is retried and does not block the photo refresh', async () => {
  const a = app();
  let fail = true;
  a.state.handlers.list_albums = () => {
    if (fail) throw new Error('albums unreadable');
    return [{ id: 'trip', name: 'Trip', created: 1 }];
  };
  a.state.photos = [photo('arrived')];
  await a.emit('library-changed', null);
  assert.equal(a.run('photos[0].id'), 'arrived');
  assert.match(a.element('importreports').textContent, /albums unreadable/);
  assert.equal(a.run('pendingImportRefresh'), true);
  fail = false;
  a.state.timers[a.run('refreshRetry') - 1].fn();
  await new Promise(setImmediate);
  assert.equal(a.run('albums[0].name'), 'Trip');
  assert.equal(a.run('pendingImportRefresh'), false);
});

test('backoff caps at 30 seconds', async () => {
  const a = app();
  a.state.handlers.list_photos = () => { throw new Error('index busy'); };
  await a.emit('library-changed', null);
  for (let i = 0; i < 8; i++) {
    a.state.timers[a.run('refreshRetry') - 1].fn();
    await new Promise(setImmediate);
  }
  assert.equal(a.run('refreshBackoff'), 30000);
  assert.equal(a.state.timers[a.run('refreshRetry') - 1].ms, 30000);
  assert.equal(a.element('importreports').children.length, 1);
});

test('lock stops a scheduled library refresh retry', async () => {
  const a = app();
  a.state.handlers.list_photos = () => { throw new Error('index busy'); };
  await a.emit('library-changed', null);
  const retry = a.state.timers[a.run('refreshRetry') - 1];
  await a.emit('vault-locked');
  assert.equal(a.run('refreshRetry'), null);
  assert.equal(a.run('pendingImportRefresh'), false);
  const listings = a.calls.filter(c => c.command === 'list_photos').length;
  retry.fn();
  await new Promise(setImmediate);
  assert.equal(a.calls.filter(c => c.command === 'list_photos').length, listings);
  assert.equal(a.run('refreshRetry'), null);
});

test('a failed album list does not block unlocking', async () => {
  const a = app();
  a.state.handlers.vault_status = () => 'unlocked';
  a.state.handlers.list_albums = () => { throw new Error('albums unreadable'); };
  a.state.photos = [photo('a')];
  await a.run('refresh()');
  assert.equal(a.element('gallery').style.display, 'block');
  assert.equal(a.run('photos[0].id'), 'a');
});

test('albums that fail to load at unlock are retried on the refresh backoff', async () => {
  const a = app();
  let failures = 2; // unlock, then the immediate retry
  a.state.handlers.vault_status = () => 'unlocked';
  a.state.handlers.list_albums = () => {
    if (failures-- > 0) throw new Error('albums unreadable');
    return [{ id: 'trip', name: 'Trip', created: 1 }];
  };
  a.state.photos = [photo('a')];
  await a.run('refresh()');
  await new Promise(setImmediate);
  assert.equal(a.element('gallery').style.display, 'block');
  assert.equal(a.run('photos[0].id'), 'a');
  assert.equal(a.run('albums.length'), 0);
  assert.equal(a.element('importreports').children.length, 1);
  assert.equal(a.state.timers[a.run('refreshRetry') - 1].ms, 1000);
  a.state.timers[a.run('refreshRetry') - 1].fn();
  await new Promise(setImmediate);
  assert.equal(a.run('albums[0].name'), 'Trip');
  assert.equal(a.run('pendingImportRefresh'), false);
  assert.equal(a.run('refreshBackoff'), 0);
  assert.equal(a.element('importreports').children.length, 1);
});

test('automatic refreshes never report user activity', async () => {
  const a = app();
  a.state.handlers.list_photos = () => { throw new Error('locked'); };
  await a.emit('library-changed', null);
  await a.emit('inbox-progress', { done: 1, total: 2 });
  await a.emit('inbox-imported', result({ imported: 1 }));
  a.state.timers[a.run('refreshRetry') - 1].fn();
  await new Promise(setImmediate);
  const commands = new Set(a.calls.map(c => c.command));
  assert.deepEqual([...commands].sort(), ['list_albums', 'list_photos']);
  assert.equal(a.element('importreports').children.length, 2);
});

test('an older album response cannot replace a newer one', async () => {
  const a = app(), listing = deferred();
  let count = 0;
  a.state.handlers.list_albums = () => ++count === 1 ? listing.promise : [{ id: 'new', name: 'New', created: 2 }];
  const first = a.run('loadAlbums()');
  await a.run('loadAlbums()');
  listing.resolve([{ id: 'old', name: 'Old', created: 1 }]);
  await first;
  assert.equal(a.run('albums.length'), 1);
  assert.equal(a.run('albums[0].id'), 'new');
});

test('Inbox progress waits while a manual import is running', async () => {
  const a = app();
  a.run('importing = true');
  a.element('toastmsg').textContent = 'Preparing import…';
  await a.emit('inbox-progress', { done: 25, total: 300 });
  assert.equal(a.element('toastmsg').textContent, 'Preparing import…');
  assert.equal(a.calls.filter(c => c.command === 'list_photos').length, 0);
});

test('an event during an ongoing refresh drains another refresh', async () => {
  const a = app(), listing = deferred();
  let count = 0;
  a.state.handlers.list_photos = () => ++count === 1 ? listing.promise : [photo('newest')];
  const first = a.emit('inbox-imported', result({ imported: 1 }));
  const second = a.emit('inbox-imported', result({ imported: 1 }));
  listing.resolve([photo('older')]);
  await Promise.all([first, second]);
  assert.equal(count, 2);
  assert.equal(a.run('photos[0].id'), 'newest');
});

test('lock clears reports and prevents pending imports or grid loads from restoring metadata', async () => {
  const a = app(), listing = deferred(), importing = deferred();
  await a.seed([photo('private')]);
  await a.run('show(0)');
  a.run('reportImport({ failed: 1, issues: [{ name: "private.jpg", reason: "unreadable" }] }, "Inbox")');
  a.state.handlers.list_photos = () => listing.promise;
  a.state.handlers.import_photos = () => importing.promise;
  const loading = a.run('loadGrid()');
  const operation = a.run('importPaths(["/private.jpg"])');
  await a.emit('vault-locked');
  listing.resolve([photo('private')]);
  importing.resolve(result({ failed: 1, issues: [{ name: 'private.jpg', reason: 'bad' }] }));
  await Promise.all([loading, operation]);
  assert.equal(a.run('photos.length'), 0);
  assert.equal(a.run('visible.length'), 0);
  assert.equal(a.element('importreports').textContent, '');
  assert.equal(a.element('gallery').style.display, 'none');
  assert.equal(a.element('lbname').textContent, '');
  assert.equal(a.element('grid').innerHTML, '');
  assert.equal(a.element('importresults').hidden, true);
});

test('a pending unlocked status cannot reopen the gallery after lock', async () => {
  const a = app(), status = deferred();
  let count = 0;
  a.state.handlers.vault_status = () => ++count === 1 ? status.promise : 'locked';
  const loading = a.run('refresh()');
  await a.emit('vault-locked');
  status.resolve('unlocked');
  await loading;
  assert.equal(a.element('gallery').style.display, 'none');
  assert.equal(a.calls.some(c => c.command === 'list_photos'), false);
});

test('lock during export dialog cancels the delayed export', async () => {
  const a = app(), dialog = deferred();
  await a.seed([photo('private')]);
  await a.run('show(0)');
  a.state.save = () => dialog.promise;
  const exporting = a.element('lbexport').onclick();
  await a.emit('vault-locked');
  dialog.resolve('/destination');
  await exporting;
  assert.equal(a.calls.some(c => c.command === 'export_photo'), false);
});

test('preflight errors report unknown counts without inventing a failed-file count', async () => {
  const a = app();
  a.state.handlers.import_photos = async () => { throw new Error('vault unavailable'); };
  await a.run('importPaths(["/a.jpg", "/b.jpg"])');
  const report = a.element('importreports').textContent;
  assert.match(report, /Import failed\. File counts are unavailable/);
  assert.match(report, /vault unavailable/);
  assert.doesNotMatch(report, /1 failed|0 imported/);
});

test('duplicate-only album imports say the existing files join the album', async () => {
  const a = app();
  a.state.handlers.import_photos = async () => result({ skipped: 2 });
  await a.run('importPaths(["/a.jpg"], "album1")');
  assert.match(a.element('importreports').textContent, /2 existing items filed into the album/);
  assert.doesNotMatch(a.element('importreports').textContent, /duplicates skipped/);
  assert.equal(a.calls.some(c => c.command === 'list_photos'), true);
});

test('an in-flight favorite cannot move a viewer the user navigated meanwhile', async () => {
  const a = app(), favorite = deferred();
  await a.seed([photo('a'), photo('b')]);
  await a.run('show(0)');
  a.state.handlers.set_favorite = () => favorite.promise;
  const favoriting = a.element('lbfav').onclick();
  await a.run('show(1)');
  favorite.resolve();
  await favoriting;
  assert.equal(a.run('viewerId'), 'b');
  assert.equal(a.run('cur'), 1);
  assert.match(a.element('lbimg').src, /\/b$/);
  assert.equal(a.element('lbfav')['aria-pressed'], 'false');
});

test('a failed favorite leaves metadata unchanged', async () => {
  const a = app();
  await a.seed([photo('a')]);
  await a.run('show(0)');
  a.state.handlers.set_favorite = async () => { throw new Error('write failed'); };
  await a.element('lbfav').onclick();
  assert.equal(a.run('photos[0].favorite'), false);
  assert.match(a.element('toastmsg').textContent, /write failed/);
});

test('overlapping list responses cannot replace a newer library with stale photos', async () => {
  const a = app(), listing = deferred();
  let count = 0;
  a.state.handlers.list_photos = () => ++count === 1 ? listing.promise : [photo('newest')];
  const first = a.run('loadGrid()');
  await a.run('loadGrid()');
  listing.resolve([photo('old')]);
  await first;
  assert.equal(a.run('photos[0].id'), 'newest');
});

test('removing the final visible photo closes the viewer', async () => {
  const a = app();
  await a.seed([photo('last')]);
  await a.run('show(0)');
  await a.element('lbdel').onclick();
  assert.equal(a.run('viewerId'), null);
  assert.equal(a.run('cur'), -1);
  assert.equal(a.element('lightbox').classList.contains('open'), false);
});

test('unfavoriting in Favorites explicitly displays the adjacent photo', async () => {
  const a = app();
  a.run('currentView = { type: "favorites" }');
  await a.seed([photo('a'), photo('b')].map(p => ({ ...p, favorite: true })));
  await a.run('show(0)');
  await a.element('lbfav').onclick();
  assert.equal(a.run('viewerId'), 'b');
  assert.equal(a.run('cur'), 0);
  assert.match(a.element('lbimg').src, /\/b$/);
});

test('repeated retry reports retain only the latest 50 batches', () => {
  const a = app();
  a.run('for (let i = 0; i < 55; i++) reportImport({ failed: 1 }, `Batch ${i}`)');
  const reports = a.element('importreports');
  assert.equal(reports.children.length, 50);
  assert.match(reports.children[0].textContent, /Batch 54:/);
  assert.match(reports.lastElementChild.textContent, /Batch 5:/);
});


test('focused library controls do not activate or delete photos through gallery shortcuts', async () => {
  const a = app();
  await a.seed([photo('a'), photo('b')]);
  a.run(`document.querySelector = () => null;
    document.activeElement = $("settingsbtn");
    document.activeElement.closest = () => document.activeElement;
    focusIdx = 0;`);
  for (const key of ['Enter', ' ', 'Delete', 'Backspace', 'ArrowRight']) a.keydown({ key });
  assert.equal(a.run('viewerId'), null);
  assert.equal(a.run('focusIdx'), 0);
  assert.equal(a.calls.some(c => c.command === 'trash_photos'), false);
});

test('viewer buttons retain arrow navigation without treating Space as a photo action', async () => {
  const a = app();
  await a.seed([photo('a'), photo('b')]);
  await a.run('show(0)');
  a.run(`document.querySelector = () => null;
    document.activeElement = $("lbfav");
    document.activeElement.closest = () => document.activeElement;`);
  a.keydown({ key: ' ' });
  assert.equal(a.run('viewerId'), 'a');
  a.keydown({ key: 'ArrowRight' });
  assert.equal(a.run('viewerId'), 'b');
  a.keydown({ key: 'ArrowLeft' });
  assert.equal(a.run('viewerId'), 'a');
});

test('opening and closing the viewer moves focus into it and returns to its caller', async () => {
  const a = app();
  await a.seed([photo('a')]);
  a.run('document.activeElement = $("viewbtn"); document.activeElement.isConnected = true;');
  await a.run('show(0)');
  assert.equal(a.element('lightbox').focusCount, 1);
  a.run('closeLightbox()');
  assert.equal(a.element('viewbtn').focusCount, 1);
});

test('failed trash preserves selection and viewer without a success toast or Undo', async () => {
  const a = app();
  await a.seed([photo('a'), photo('b')]);
  a.run('selection = new Set(["a"]); show(0)');
  a.state.handlers.trash_photos = async () => { throw new Error('index write failed'); };
  const listings = a.calls.filter(c => c.command === 'list_photos').length;
  await a.element('seldelete').onclick();
  assert.deepEqual(Array.from(a.run('selectedIds()')), ['a']);
  assert.equal(a.run('viewerId'), 'a');
  assert.equal(a.calls.filter(c => c.command === 'list_photos').length, listings);
  assert.match(a.element('toastmsg').textContent, /index write failed/);
  assert.doesNotMatch(a.element('toastmsg').textContent, /Moved/);
  assert.equal(a.element('toastact').style.display, 'none');
});

for (const [button, command] of [['selrestore', 'restore_photos'], ['selpurge', 'purge_photos'], ['lbrestore', 'restore_photos'], ['lbpurge', 'purge_photos']]) {
  test(`${button} retains current state when ${command} fails`, async () => {
    const a = app();
    a.run('currentView = { type: "trash" }');
    await a.seed([{ ...photo('a'), deleted: 100 }]);
    a.run('selection = new Set(["a"]); show(0)');
    a.state.handlers[command] = async () => { throw new Error('cannot persist'); };
    const listings = a.calls.filter(c => c.command === 'list_photos').length;
    await a.element(button).onclick();
    assert.deepEqual(Array.from(a.run('selectedIds()')), ['a']);
    assert.equal(a.run('viewerId'), 'a');
    assert.equal(a.calls.filter(c => c.command === 'list_photos').length, listings);
    assert.match(a.element('toastmsg').textContent, /cannot persist/);
  });
}

test('failed Undo is visible and cannot be used after the session locks', async () => {
  const a = app();
  await a.seed([photo('a')]);
  await a.run('trashIds(["a"])');
  a.state.handlers.restore_photos = async () => { throw new Error('restore failed'); };
  const undo = a.element('toastact').onclick;
  undo();
  await new Promise(setImmediate);
  assert.match(a.element('toastmsg').textContent, /restore failed/);
  const calls = a.calls.filter(c => c.command === 'restore_photos').length;
  await a.emit('vault-locked');
  undo();
  await new Promise(setImmediate);
  assert.equal(a.calls.filter(c => c.command === 'restore_photos').length, calls);
});

test('successful trash does not clear unrelated selections added during the request', async () => {
  const a = app(), deleting = deferred();
  await a.seed([photo('a'), photo('b')]);
  a.run('selection = new Set(["a"])');
  a.state.handlers.trash_photos = () => deleting.promise;
  const operation = a.element('seldelete').onclick();
  a.element('selalbum').parentElement = { style: {} };
  a.run('selection.add("b")');
  deleting.resolve();
  await operation;
  assert.deepEqual(Array.from(a.run('selectedIds()')), ['b']);
});

test('partial export persists counts and safely renders per-file errors', async () => {
  const a = app();
  await a.seed([photo('a'), photo('b')]);
  a.run('selection = new Set(["a", "b"])');
  a.state.open = async () => '/export';
  a.state.handlers.export_photos = async () => ({ exported: 1, failed: 1, issues: [
    { name: '<img src=x onerror=alert(1)>.jpg', reason: 'Cannot decrypt <original>' },
  ] });
  await a.element('selexport').onclick();
  const report = a.element('importreports').children[0];
  assert.match(report.textContent, /1 exported, 1 failed/);
  assert.equal(report.open, true);
  const row = report.children.find(e => e.tagName === 'UL').children[0];
  assert.equal(row.innerHTML, '');
  assert.match(row.textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(a.element('importresults').hidden, false);
  const summary = a.element('toastmsg').textContent;
  await a.emit('export-progress', { done: 2, total: 2 });
  assert.equal(a.element('toastmsg').textContent, summary);
});

test('all-failed exports and command failures retain distinct accurate reports', async () => {
  const a = app();
  a.state.open = async () => '/export';
  a.state.handlers.export_photos = async () => ({ exported: 0, failed: 3, issues: [] });
  await a.element('exportallbtn').onclick();
  assert.match(a.element('importreports').children[0].textContent, /0 exported, 3 failed/);
  assert.equal(a.calls.find(c => c.command === 'export_photos').args.ids, null);
  a.state.handlers.export_photos = async () => { throw new Error('locked'); };
  await a.element('exportallbtn').onclick();
  const report = a.element('importreports').children[0].textContent;
  assert.match(report, /File counts are unavailable.*locked/);
  assert.doesNotMatch(report, /0 exported|1 failed/);
});

test('bulk export snapshots selection before the picker and guards session changes', async () => {
  const a = app(), picker = deferred();
  await a.seed([photo('a'), photo('b')]);
  a.run('selection = new Set(["a"])');
  a.state.open = () => picker.promise;
  a.state.handlers.export_photos = async () => ({ exported: 1, failed: 0, issues: [] });
  const operation = a.element('selexport').onclick();
  a.run('selection = new Set(["b"])');
  picker.resolve('/export');
  await operation;
  assert.deepEqual(Array.from(a.calls.find(c => c.command === 'export_photos').args.ids), ['a']);
  const pending = deferred();
  a.state.open = () => pending.promise;
  const canceled = a.element('exportallbtn').onclick();
  await a.emit('vault-locked');
  pending.resolve('/export');
  await canceled;
  assert.equal(a.calls.filter(c => c.command === 'export_photos').length, 1);
});

test('completed export cannot restore filenames or progress after lock', async () => {
  const a = app(), exporting = deferred();
  a.state.open = async () => '/export';
  a.state.handlers.export_photos = () => exporting.promise;
  const operation = a.element('exportallbtn').onclick();
  await new Promise(setImmediate);
  await a.emit('vault-locked');
  exporting.resolve({ exported: 0, failed: 1, issues: [{ name: 'private.jpg', reason: 'unreadable' }] });
  await operation;
  await a.emit('export-progress', { done: 1, total: 1 });
  assert.equal(a.element('importreports').textContent, '');
  assert.equal(a.run('activeExports'), 0);
  assert.equal(a.element('toastmsg').textContent, 'Vault locked');
});

test('lock during purge confirmation prevents the delayed mutation', async () => {
  const a = app(), confirmation = deferred();
  await a.seed([{ ...photo('a'), deleted: 100 }]);
  a.run('selection = new Set(["a"])');
  a.state.ask = () => confirmation.promise;
  const operation = a.element('selpurge').onclick();
  await a.emit('vault-locked');
  confirmation.resolve(true);
  await operation;
  assert.equal(a.calls.some(c => c.command === 'purge_photos'), false);
});

test('failed Delete All preserves the displayed library and selection', async () => {
  const a = app();
  await a.seed([photo('a')]);
  a.run('selection = new Set(["a"]); show(0)');
  a.state.handlers.clear_vault = async () => { throw new Error('cannot write index'); };
  await a.element('clearbtn').onclick();
  assert.equal(a.run('photos.length'), 1);
  assert.equal(a.run('viewerId'), 'a');
  assert.deepEqual(Array.from(a.run('selectedIds()')), ['a']);
  assert.match(a.element('toastmsg').textContent, /cannot write index/);
  assert.doesNotMatch(a.element('toastmsg').textContent, /Deleted 1/);
});

test('lock during Delete All confirmation prevents the mutation', async () => {
  const a = app(), confirmation = deferred();
  await a.seed([photo('a')]);
  a.state.ask = () => confirmation.promise;
  const operation = a.element('clearbtn').onclick();
  await a.emit('vault-locked');
  confirmation.resolve(true);
  await operation;
  assert.equal(a.calls.some(c => c.command === 'clear_vault'), false);
});

test('recovery notice remains visible through refresh and clears on lock', async () => {
  const a = app();
  a.state.handlers.vault_status = () => 'unlocked';
  a.state.handlers.recovery_status = () => true;
  await a.run('refresh()');
  assert.equal(a.element('recoverynotice').hidden, false);
  await a.run('loadGrid()');
  assert.equal(a.element('recoverynotice').hidden, false);
  await a.run('refresh()');
  assert.equal(a.element('recoverynotice').hidden, false);
  a.run('clearVaultUI()');
  assert.equal(a.element('recoverynotice').hidden, true);
  a.state.handlers.recovery_status = () => false;
  await a.run('refresh()');
  assert.equal(a.element('recoverynotice').hidden, true);
});

test('late recovery status cannot reveal a notice after lock', async () => {
  const a = app(), status = deferred();
  a.state.handlers.vault_status = () => 'unlocked';
  a.state.handlers.recovery_status = () => status.promise;
  const refreshing = a.run('refresh()');
  await Promise.resolve();
  await Promise.resolve();
  a.run('clearVaultUI()');
  status.resolve(true);
  await refreshing;
  assert.equal(a.element('recoverynotice').hidden, true);
});

for (const [button, lock] of [['offeryes', 'event'], ['rkgen', 'clearVaultUI']]) {
  test(`a recovery key from ${button} that arrives after lock (${lock}) is never shown`, async () => {
    const a = app(), generating = deferred();
    a.state.handlers.recovery_generate = () => generating.promise;
    const operation = a.element(button).onclick();
    if (lock === 'event') await a.emit('vault-locked');
    else a.run('clearVaultUI()');
    generating.resolve({ key: 'SECRET-RECOVERY-KEY', id: 'new' });
    await operation;
    assert.equal(a.element('keymodal').classList.contains('open'), false);
    assert.equal(a.element('rkey').textContent, '');
  });
}

test('a recovery key error after lock does not toast or refresh again', async () => {
  const a = app(), generating = deferred();
  a.state.handlers.recovery_generate = () => generating.promise;
  const operation = a.element('offeryes').onclick();
  a.run('clearVaultUI()');
  generating.reject(new Error('vault locked'));
  await operation;
  assert.equal(a.element('toastmsg').textContent, '');
  assert.equal(a.calls.some(c => c.command === 'vault_status'), false);
});

test('lock wipes a shown recovery key and typed passwords', () => {
  const a = app();
  a.run('showRecoveryKey("SECRET-RECOVERY-KEY", "new", false)');
  for (const id of ['cpw0', 'cpw1', 'cpw2']) a.element(id).value = 'hunter22';
  a.element('pminput').value = 'Private album';
  a.run('clearVaultUI()');
  assert.equal(a.element('keymodal').classList.contains('open'), false);
  assert.equal(a.element('rkey').textContent, '');
  for (const id of ['cpw0', 'cpw1', 'cpw2', 'pminput']) assert.equal(a.element(id).value, '');
});

test('Done saves the new recovery key and then refreshes recovery status', async () => {
  const a = app();
  a.state.handlers.lock_screen_info = () => ({ has_recovery: true });
  a.run('showRecoveryKey("NEW-KEY", "new", false)');
  await a.element('rkdone').onclick();
  assert.deepEqual(a.calls.filter(c => c.command === 'recovery_confirm').map(c => c.args.id), ['new']);
  assert.equal(a.element('keymodal').classList.contains('open'), false);
  assert.equal(a.element('rkey').textContent, '');
  await new Promise(setImmediate);
  assert.equal(a.run('$("rkgen").textContent'), 'Regenerate…');
});

test('Done after the setup offer saves the key and then finishes unlocking', async () => {
  const a = app();
  a.run('showRecoveryKey("NEW-KEY", "new", true)');
  await a.element('rkdone').onclick();
  const commands = a.calls.map(c => c.command);
  assert.ok(commands.indexOf('recovery_confirm') < commands.indexOf('vault_status'));
  assert.equal(a.element('keymodal').classList.contains('open'), false);
});

test('a failed confirm keeps the new key on screen and says the old key still works', async () => {
  const a = app();
  a.state.handlers.recovery_confirm = () => { throw new Error('disk full'); };
  a.run('showRecoveryKey("NEW-KEY", "new", false)');
  await a.element('rkdone').onclick();
  assert.equal(a.element('keymodal').classList.contains('open'), true);
  assert.equal(a.element('rkey').textContent, 'NEW-KEY');
  assert.match(a.element('toastmsg').textContent, /Couldn't save the new recovery key.*old key still works/);
  assert.equal(a.element('rkdone').disabled, false);
  assert.equal(a.calls.some(c => c.command === 'lock_screen_info'), false);
});

for (const outcome of ['resolve', 'reject']) {
  test(`a confirm that settles after lock (${outcome}) shows nothing`, async () => {
    const a = app(), confirming = deferred();
    a.state.handlers.recovery_confirm = () => confirming.promise;
    a.run('showRecoveryKey("NEW-KEY", "new", true)');
    const operation = a.element('rkdone').onclick();
    a.run('clearVaultUI()');
    if (outcome === 'resolve') confirming.resolve(null);
    else confirming.reject(new Error('locked'));
    await operation;
    assert.equal(a.element('keymodal').classList.contains('open'), false);
    assert.equal(a.element('rkey').textContent, '');
    assert.equal(a.element('toastmsg').textContent, '');
    assert.equal(a.calls.some(c => c.command === 'vault_status' || c.command === 'lock_screen_info'), false);
  });
}

test('only the latest Generate response is shown, and Done saves that key', async () => {
  const a = app(), first = deferred(), second = deferred();
  const responses = [first, second];
  a.state.handlers.recovery_generate = () => responses.shift().promise;
  const older = a.element('rkgen').onclick();
  const newer = a.element('rkgen').onclick();
  second.resolve({ key: 'KEY-B', id: 'b' });
  await newer;
  // The first request answers last. It must not replace the key on screen.
  first.resolve({ key: 'KEY-A', id: 'a' });
  await older;
  assert.equal(a.element('rkey').textContent, 'KEY-B');
  await a.element('rkdone').onclick();
  assert.deepEqual(a.calls.filter(c => c.command === 'recovery_confirm').map(c => c.args.id), ['b']);
});

test('a confirm that replaced the key without a disk sync keeps it on screen until closed', async () => {
  const a = app();
  a.element('keymodal').id = 'keymodal';
  a.run(`document.querySelectorAll = sel => sel === ".modal.open" && $("keymodal").classList.contains("open")
    ? [$("keymodal")] : [];`);
  const warning = "Saved, but the disk didn't confirm the write. Keep this new key; any old key no longer works.";
  a.state.handlers.recovery_confirm = () => ({ warning });
  a.run('showRecoveryKey("NEW-KEY", "new", false)');
  await a.element('rkdone').onclick();
  assert.equal(a.element('keymodal').classList.contains('open'), true);
  assert.equal(a.element('rkey').textContent, 'NEW-KEY');
  assert.equal(a.element('rkwarn').hidden, false);
  assert.equal(a.element('rkwarn').textContent, warning);
  assert.doesNotMatch(a.element('toastmsg').textContent, /old key still works/);
  // The key is saved, so closing doesn't claim it wasn't, and Done doesn't save again.
  await a.keydown({ key: 'Escape' });
  assert.equal(a.element('keymodal').classList.contains('open'), false);
  assert.equal(a.element('rkey').textContent, '');
  assert.doesNotMatch(a.element('toastmsg').textContent, /not changed/);
  a.run('showRecoveryKey("OTHER-KEY", "other", false)');
  assert.equal(a.element('rkwarn').hidden, true);
  a.state.handlers.recovery_confirm = () => ({ warning });
  await a.element('rkdone').onclick();
  await a.element('rkdone').onclick();
  assert.equal(a.calls.filter(c => c.command === 'recovery_confirm').length, 2);
  assert.equal(a.element('keymodal').classList.contains('open'), false);
});

test('Escape closes the recovery key without saving it', async () => {
  const a = app();
  a.element('keymodal').id = 'keymodal';
  a.run(`document.querySelectorAll = sel => sel === ".modal.open" && $("keymodal").classList.contains("open")
    ? [$("keymodal")] : [];`);
  a.run('showRecoveryKey("NEW-KEY", "new", false)');
  await a.keydown({ key: 'Escape' });
  assert.equal(a.calls.some(c => c.command === 'recovery_confirm'), false);
  assert.equal(a.element('keymodal').classList.contains('open'), false);
  assert.equal(a.element('rkey').textContent, '');
  assert.match(a.element('toastmsg').textContent, /Recovery key not changed/);
});

test('Escape while Done is saving leaves the key modal alone', async () => {
  const a = app(), confirming = deferred();
  a.state.handlers.recovery_confirm = () => confirming.promise;
  a.element('keymodal').id = 'keymodal';
  a.run(`document.querySelectorAll = sel => sel === ".modal.open" && $("keymodal").classList.contains("open")
    ? [$("keymodal")] : [];`);
  a.run('showRecoveryKey("NEW-KEY", "new", false)');
  const operation = a.element('rkdone').onclick();
  await a.keydown({ key: 'Escape' });
  assert.equal(a.element('keymodal').classList.contains('open'), true);
  assert.equal(a.element('toastmsg').textContent, '');
  confirming.resolve(null);
  await operation;
  assert.equal(a.element('keymodal').classList.contains('open'), false);
  assert.equal(a.element('toastmsg').textContent, '');
});

test('settings cannot open over the lock screen after a slow load', async () => {
  const a = app(), available = deferred();
  a.state.handlers.touchid_available = () => available.promise;
  const opening = a.element('settingsbtn').onclick();
  await a.emit('vault-locked');
  available.resolve(true);
  await opening;
  assert.equal(a.element('settings').classList.contains('open'), false);
});
