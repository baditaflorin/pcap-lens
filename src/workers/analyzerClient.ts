import type { AnalyzerWorkerApi } from './analyzer.worker';
import { type Remote, wrap } from 'comlink';

let workerClient: Remote<AnalyzerWorkerApi> | undefined;

export function analyzerClient(): Remote<AnalyzerWorkerApi> {
  if (!workerClient) {
    const worker = new Worker(new URL('./analyzer.worker.ts', import.meta.url), {
      type: 'module'
    });
    workerClient = wrap<AnalyzerWorkerApi>(worker);
  }

  return workerClient;
}
