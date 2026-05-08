import { execSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));

function run(command, fallback) {
  try {
    return execSync(command, { encoding: 'utf8' }).trim();
  } catch {
    return fallback;
  }
}

mkdirSync('public', { recursive: true });
writeFileSync(
  'public/version.json',
  `${JSON.stringify(
    {
      version: pkg.version,
      commit: run('git rev-parse --short HEAD', 'dev'),
      generatedAt: new Date().toISOString(),
      repository: 'https://github.com/baditaflorin/pcap-lens'
    },
    null,
    2
  )}\n`
);
