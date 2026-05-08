import { rmSync } from 'node:fs';

const paths = [
  'docs/assets',
  'docs/index.html',
  'docs/404.html',
  'docs/manifest.webmanifest',
  'docs/icon.svg',
  'docs/service-worker.js',
  'docs/version.json'
];

for (const path of paths) {
  rmSync(path, { force: true, recursive: true });
}
