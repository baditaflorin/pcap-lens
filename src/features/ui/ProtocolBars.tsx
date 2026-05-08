import type { ProtocolCount } from '@/features/analyzer/types';
import { formatBytes } from '@/lib/format';

interface ProtocolBarsProps {
  counts: ProtocolCount[];
}

export function ProtocolBars({ counts }: ProtocolBarsProps) {
  const max = Math.max(...counts.map((count) => count.packets), 1);

  return (
    <div className="panel p-4">
      <h2 className="section-title">Protocols</h2>
      <div className="mt-4 space-y-3">
        {counts.map((count) => (
          <div key={count.protocol}>
            <div className="mb-1 flex items-center justify-between gap-3 text-sm">
              <span className="font-semibold">{count.protocol}</span>
              <span className="text-slate-500">
                {count.packets} · {formatBytes(count.bytes)}
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded bg-slate-200">
              <div
                className="h-full rounded bg-reef"
                style={{ width: `${Math.max(6, (count.packets / max) * 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
