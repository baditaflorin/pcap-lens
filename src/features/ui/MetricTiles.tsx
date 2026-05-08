import type { AnalysisResult } from '@/features/analyzer/types';
import { formatBytes } from '@/lib/format';
import { Activity, Boxes, Network, ShieldCheck, TriangleAlert } from 'lucide-react';

interface MetricTilesProps {
  result: AnalysisResult;
  warningCount: number;
}

export function MetricTiles({ result, warningCount }: MetricTilesProps) {
  const metrics = [
    {
      label: 'Packets',
      value: result.summary.packetCount.toLocaleString(),
      icon: Activity
    },
    {
      label: 'Flows',
      value: result.summary.flowCount.toLocaleString(),
      icon: Network
    },
    {
      label: 'Bytes',
      value: formatBytes(result.summary.totalBytes),
      icon: Boxes
    },
    {
      label: 'Rule hits',
      value: result.summary.ruleMatchCount.toLocaleString(),
      icon: ShieldCheck
    },
    {
      label: 'Warnings',
      value: warningCount.toLocaleString(),
      icon: TriangleAlert
    }
  ];

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      {metrics.map((metric) => {
        const Icon = metric.icon;
        return (
          <div className="metric-tile" key={metric.label}>
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm font-semibold text-slate-600">{metric.label}</span>
              <Icon size={18} className="text-reef" aria-hidden="true" />
            </div>
            <div className="mt-2 text-2xl font-bold tracking-normal">{metric.value}</div>
          </div>
        );
      })}
    </div>
  );
}
