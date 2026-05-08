import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));

mkdirSync('public', { recursive: true });
writeFileSync(
  'public/version.json',
  `${JSON.stringify(
    {
      version: pkg.version,
      commit: process.env.BUILD_COMMIT ?? 'offline',
      repository: 'https://github.com/baditaflorin/pcap-lens'
    },
    null,
    2
  )}\n`
);
