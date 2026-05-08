import type { AnalysisResult } from '@/features/analyzer/types';
import { AlertTriangle, ShieldAlert } from 'lucide-react';

interface RuleFindingsProps {
  result: AnalysisResult;
}

export function RuleFindings({ result }: RuleFindingsProps) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="section-title">IDS Matches</h2>
        <span className="rounded bg-amber-100 px-2 py-1 text-xs font-bold text-amber-900">
          {result.rules.matches.length}
        </span>
      </div>

      {result.rules.errors.length > 0 ? (
        <div className="mt-3 space-y-2">
          {result.rules.errors.map((error) => (
            <div
              className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm"
              key={error.line}
            >
              <div className="flex items-start gap-2 font-semibold text-amber-900">
                <AlertTriangle size={16} aria-hidden="true" />
                Line {error.line}: {error.message}
              </div>
            </div>
          ))}
        </div>
      ) : null}

      <div className="mt-3 grid gap-2 md:grid-cols-2">
        {result.rules.matches.slice(0, 12).map((match) => (
          <div
            className="rounded-lg border border-slate-200 bg-white p-3 shadow-panel"
            key={match.id}
          >
            <div className="flex items-start gap-2">
              <ShieldAlert className="mt-0.5 text-signal" size={17} aria-hidden="true" />
              <div>
                <div className="font-semibold">{match.message}</div>
                <div className="mt-1 text-xs text-slate-500">
                  sid:{match.sid} · packet #{match.packetIndex} · {match.protocol}
                </div>
                <div className="mt-2 text-sm text-slate-700">{match.summary}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {result.rules.matches.length === 0 && result.rules.errors.length === 0 ? (
        <p className="mt-3 text-sm text-slate-600">No IDS matches.</p>
      ) : null}
    </div>
  );
}
