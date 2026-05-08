import { useCallback, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  ExternalLink,
  FileSearch,
  Heart,
  Loader2,
  Play,
  RefreshCw,
  ShieldAlert,
  Star,
  Upload
} from 'lucide-react';
import type { AnalysisResult } from '@/features/analyzer/types';
import { DEFAULT_RULES } from '@/features/rules/suricata';
import { createSampleCapture } from '@/features/sample/sampleCapture';
import { FlowGraph } from '@/features/ui/FlowGraph';
import { MetricTiles } from '@/features/ui/MetricTiles';
import { PacketTable } from '@/features/ui/PacketTable';
import { ProtocolBars } from '@/features/ui/ProtocolBars';
import { RuleEditor } from '@/features/ui/RuleEditor';
import { RuleFindings } from '@/features/ui/RuleFindings';
import { asUserMessage } from '@/lib/errors';
import { fetchVersionMetadata, PAYPAL_URL, REPOSITORY_URL } from '@/lib/metadata';
import { clearRules, loadRules, saveRules } from '@/lib/storage';
import { analyzerClient } from '@/workers/analyzerClient';

export function App() {
  const [rulesText, setRulesText] = useState(() => loadRules());
  const [result, setResult] = useState<AnalysisResult | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const version = useQuery({
    queryKey: ['version-metadata'],
    queryFn: fetchVersionMetadata
  });

  const analyzeBuffer = useCallback(
    async (buffer: ArrayBuffer, fileName: string) => {
      setBusy(true);
      setError(undefined);

      try {
        const analysis = await analyzerClient().analyze(buffer, fileName, rulesText);
        setResult(analysis);
      } catch (unknownError) {
        setError(asUserMessage(unknownError));
      } finally {
        setBusy(false);
      }
    },
    [rulesText]
  );

  const onFile = useCallback(
    async (file: File) => {
      await analyzeBuffer(await file.arrayBuffer(), file.name);
    },
    [analyzeBuffer]
  );

  const resetRules = useCallback(() => {
    clearRules();
    setRulesText(DEFAULT_RULES);
  }, []);

  const handleRulesChange = useCallback((value: string) => {
    setRulesText(value);
    saveRules(value);
  }, []);

  const warningCount = useMemo(() => {
    return (
      (result?.summary.warnings.length ?? 0) +
      (result?.packets.reduce((sum, packet) => sum + packet.warnings.length, 0) ?? 0) +
      (result?.rules.errors.length ?? 0)
    );
  }, [result]);

  return (
    <div className="min-h-screen bg-slate-50 text-ink">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-4 py-4 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <div className="grid size-10 place-items-center rounded-lg bg-[#12343b] text-white">
              <FileSearch aria-hidden="true" size={22} />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-normal">pcap-lens</h1>
              <p className="text-sm text-slate-600">Local packet capture analyzer</p>
            </div>
          </div>

          <nav className="flex flex-wrap items-center gap-2" aria-label="Project links">
            <a
              className="button button-secondary"
              href={REPOSITORY_URL}
              target="_blank"
              rel="noreferrer"
            >
              <Star size={17} aria-hidden="true" />
              Star on GitHub
              <ExternalLink size={14} aria-hidden="true" />
            </a>
            <a
              className="button button-support"
              href={PAYPAL_URL}
              target="_blank"
              rel="noreferrer"
            >
              <Heart size={17} aria-hidden="true" />
              Support
              <ExternalLink size={14} aria-hidden="true" />
            </a>
          </nav>
        </div>
      </header>

      <main className="mx-auto grid max-w-7xl gap-4 px-4 py-4 xl:grid-cols-[390px_minmax(0,1fr)]">
        <section className="space-y-4" aria-label="Capture controls">
          <div
            className={`panel p-4 ${dragging ? 'border-reef bg-teal-50' : ''}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragging(false);
              const file = event.dataTransfer.files.item(0);
              if (file) {
                void onFile(file);
              }
            }}
          >
            <input
              ref={inputRef}
              className="sr-only"
              type="file"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
              onChange={(event) => {
                const file = event.currentTarget.files?.item(0);
                if (file) {
                  void onFile(file);
                }
              }}
            />

            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="section-title">Capture</h2>
                <p className="mt-1 text-sm text-slate-600">Drop `.pcap` or `.pcapng`</p>
              </div>
              <Upload className="text-reef" aria-hidden="true" size={24} />
            </div>

            <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
              <button
                className="button button-primary"
                type="button"
                onClick={() => inputRef.current?.click()}
              >
                <Upload size={17} aria-hidden="true" />
                Select capture
              </button>
              <button
                className="button button-secondary"
                type="button"
                onClick={() =>
                  void analyzeBuffer(createSampleCapture(), 'synthetic-http-dns-tls.pcap')
                }
              >
                <Play size={17} aria-hidden="true" />
                Load sample
              </button>
            </div>
          </div>

          <RuleEditor value={rulesText} onChange={handleRulesChange} onReset={resetRules} />

          <div className="panel p-4">
            <h2 className="section-title">Build</h2>
            <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 text-sm">
              <dt className="text-slate-500">Version</dt>
              <dd className="font-mono">{version.data?.version ?? '0.1.0'}</dd>
              <dt className="text-slate-500">Commit</dt>
              <dd className="font-mono">{version.data?.commit ?? 'loading'}</dd>
              <dt className="text-slate-500">Source</dt>
              <dd>{version.data?.source === 'github' ? 'GitHub main' : 'build metadata'}</dd>
            </dl>
          </div>
        </section>

        <section className="space-y-4" aria-label="Analysis workspace">
          {busy ? (
            <div className="panel grid min-h-[420px] place-items-center p-6">
              <div className="flex items-center gap-3 text-slate-700">
                <Loader2 className="animate-spin text-reef" size={24} aria-hidden="true" />
                <span className="font-semibold">Analyzing capture</span>
              </div>
            </div>
          ) : error ? (
            <div className="panel border-signal bg-red-50 p-5 text-signal" role="alert">
              <div className="flex items-start gap-3">
                <AlertTriangle aria-hidden="true" />
                <div>
                  <h2 className="font-bold">Analysis failed</h2>
                  <p className="mt-1 text-sm">{error}</p>
                </div>
              </div>
            </div>
          ) : result ? (
            <>
              <MetricTiles result={result} warningCount={warningCount} />
              <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(320px,0.9fr)]">
                <FlowGraph graph={result.graph} />
                <ProtocolBars counts={result.protocolCounts} />
              </div>
              <RuleFindings result={result} />
              <PacketTable packets={result.packets} />
            </>
          ) : (
            <div className="panel grid min-h-[420px] place-items-center p-6">
              <div className="max-w-md text-center">
                <ShieldAlert className="mx-auto text-reef" size={42} aria-hidden="true" />
                <h2 className="mt-4 text-xl font-bold tracking-normal">Ready</h2>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  Local decode, flow graph, and IDS rule matching run after a capture is
                  selected.
                </p>
                <button
                  className="button button-primary mx-auto mt-5"
                  type="button"
                  onClick={() =>
                    void analyzeBuffer(createSampleCapture(), 'synthetic-http-dns-tls.pcap')
                  }
                >
                  <RefreshCw size={17} aria-hidden="true" />
                  Run sample
                </button>
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
