import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const copies = readFileSync(path.join(root, 'Dockerfile'), 'utf8')
  .split(/\r?\n/)
  .filter((line) => /^COPY\s/.test(line))
  .map((line) => {
    const args = line.trim().split(/\s+/).slice(1);
    const from = args.find((arg) => arg.startsWith('--from='))?.slice('--from='.length);
    const paths = args.filter((arg) => !arg.startsWith('--'));
    return { from, sources: paths.slice(0, -1) };
  });

test('Docker build context contains every local COPY source', () => {
  const missing = copies
    .filter(({ from }) => !from)
    .flatMap(({ sources }) => sources)
    .filter((source) => !existsSync(path.join(root, source)));
  assert.deepEqual(missing, [], 'Docker COPY references missing build-context files');
});

test('Docker runtime copies package manifests that still exist in the builder', () => {
  const missing = copies
    .filter(({ from }) => from === 'builder')
    .flatMap(({ sources }) => sources)
    .filter((source) => source.endsWith('/package.json'))
    .filter((source) => !existsSync(path.join(root, path.posix.relative('/app', source))));
  assert.deepEqual(missing, [], 'Docker runtime references deleted workspace manifests');
});
