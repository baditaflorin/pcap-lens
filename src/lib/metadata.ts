declare const __APP_VERSION__: string;
declare const __GIT_COMMIT__: string;

export const APP_VERSION = __APP_VERSION__;
export const BUILT_COMMIT = __GIT_COMMIT__;
export const REPOSITORY_URL =
  import.meta.env.VITE_REPOSITORY_URL ?? 'https://github.com/baditaflorin/pcap-lens';
export const PAYPAL_URL =
  import.meta.env.VITE_PAYPAL_URL ?? 'https://www.paypal.com/paypalme/florinbadita';

export interface VersionMetadata {
  version: string;
  commit: string;
  source: 'github' | 'build';
}

export async function fetchVersionMetadata(): Promise<VersionMetadata> {
  try {
    const response = await fetch(
      'https://api.github.com/repos/baditaflorin/pcap-lens/commits/main',
      {
        headers: { Accept: 'application/vnd.github+json' }
      }
    );

    if (response.ok) {
      const data = (await response.json()) as { sha?: string };
      if (data.sha) {
        return {
          version: APP_VERSION,
          commit: data.sha.slice(0, 7),
          source: 'github'
        };
      }
    }
  } catch {
    // The build metadata fallback keeps the footer useful offline and under API rate limits.
  }

  return {
    version: APP_VERSION,
    commit: BUILT_COMMIT,
    source: 'build'
  };
}
