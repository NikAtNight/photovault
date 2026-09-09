const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { test } = require('node:test');

const root = join(__dirname, '..');
const buildScript = readFileSync(join(root, 'src-tauri/build.rs'), 'utf8');

test('build identifier changes with source contents, including untracked files', t => {
  const temp = mkdtempSync(join(tmpdir(), 'photovault-build-info-'));
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  const fixture = join(temp, 'project');
  const inputs = buildScript.match(/const BUILD_INPUTS:[\s\S]*?= &\[([\s\S]*?)\];/)[1];
  for (const [, input] of inputs.matchAll(/"([^"]+)"/g)) {
    const dest = join(fixture, input);
    mkdirSync(require('node:path').dirname(dest), { recursive: true });
    cpSync(join(root, input), dest, { recursive: true });
  }
  // Run the real metadata generator without compiling Tauri or opening a vault.
  const harness = join(temp, 'build.rs');
  const executable = join(temp, 'build-info');
  writeFileSync(harness, buildScript + '\nmod tauri_build { pub fn build() {} }\n');
  execFileSync('rustc', ['--edition=2021', harness, '-o', executable]);
  const metadata = project => execFileSync(executable, {
    env: { ...process.env, CARGO_MANIFEST_DIR: join(project, 'src-tauri') },
    encoding: 'utf8',
  });
  const id = () => metadata(fixture).match(/PHOTOVAULT_BUILD_ID=(.+)/)[1];
  const baseline = id();
  assert.match(baseline, /^source-[a-f0-9]{16}$/);
  assert.equal(id(), baseline, 'identical inputs retain their identifier');

  for (const input of ['ui/index.html', 'src-tauri/src/main.rs', 'src-tauri/tauri.conf.json']) {
    const path = join(fixture, input);
    const original = readFileSync(path);
    writeFileSync(path, Buffer.concat([original, Buffer.from('\n ')]));
    assert.notEqual(id(), baseline, `${input} must affect the identifier`);
    writeFileSync(path, original);
    assert.equal(id(), baseline, 'restored contents retain identity despite new modification times');
  }
  const added = join(fixture, 'ui/new-file.txt');
  writeFileSync(added, 'untracked input');
  assert.notEqual(id(), baseline);
  rmSync(added);
  assert.equal(id(), baseline);

  const actual = metadata(root);
  const head = execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  assert.ok(actual.includes(`PHOTOVAULT_BUILD_ID=${head}-`));
  for (const input of ['HEAD', 'refs']) {
    const path = execFileSync('git', ['rev-parse', '--path-format=absolute', '--git-path', input], {
      cwd: root, encoding: 'utf8',
    }).trim();
    assert.ok(actual.includes(`cargo:rerun-if-changed=${path}`), `${input} must trigger fresh metadata`);
  }
});
