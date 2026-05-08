import { analyzeCapture } from '@/features/analyzer/analyze';
import type { AnalysisResult } from '@/features/analyzer/types';
import { expose } from 'comlink';

export interface AnalyzerWorkerApi {
  analyze(buffer: ArrayBuffer, fileName: string, rulesText: string): AnalysisResult;
}

const api: AnalyzerWorkerApi = {
  analyze(buffer, fileName, rulesText) {
    return analyzeCapture(buffer, fileName, rulesText);
  }
};

expose(api);
