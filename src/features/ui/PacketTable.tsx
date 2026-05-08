import { useMemo, useState } from 'react';
import type { DecodedPacket } from '@/features/analyzer/types';
import { formatBytes } from '@/lib/format';

interface PacketTableProps {
  packets: DecodedPacket[];
}

export function PacketTable({ packets }: PacketTableProps) {
  const [protocolFilter, setProtocolFilter] = useState('all');
  const protocols = useMemo(
    () => [...new Set(packets.map((packet) => packet.protocol))].sort(),
    [packets]
  );
  const visiblePackets = packets
    .filter((packet) => protocolFilter === 'all' || packet.protocol === protocolFilter)
    .slice(0, 200);

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-slate-200 p-4 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="section-title">Packets</h2>
        <label className="flex items-center gap-2 text-sm">
          <span className="text-slate-500">Protocol</span>
          <select
            className="rounded-lg border border-slate-300 bg-white px-2 py-1.5 outline-none ring-reef/30 focus:ring-4"
            value={protocolFilter}
            onChange={(event) => setProtocolFilter(event.currentTarget.value)}
          >
            <option value="all">All</option>
            {protocols.map((protocol) => (
              <option key={protocol} value={protocol}>
                {protocol}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-100 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-4 py-3">#</th>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Protocol</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Destination</th>
              <th className="px-4 py-3">Length</th>
              <th className="px-4 py-3">Summary</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {visiblePackets.map((packet) => (
              <tr
                className={packet.matchedRuleIds.length > 0 ? 'bg-amber-50' : 'bg-white'}
                key={packet.index}
              >
                <td className="px-4 py-3 font-mono text-xs">{packet.index}</td>
                <td className="px-4 py-3 font-mono text-xs">{packet.timestampIso}</td>
                <td className="px-4 py-3">
                  <span className="rounded bg-slate-100 px-2 py-1 text-xs font-bold">
                    {packet.protocol}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs">
                  {endpoint(packet.source, packet.sourcePort)}
                </td>
                <td className="px-4 py-3 font-mono text-xs">
                  {endpoint(packet.destination, packet.destinationPort)}
                </td>
                <td className="px-4 py-3">{formatBytes(packet.originalLength)}</td>
                <td className="max-w-xl px-4 py-3">
                  <div>{packet.summary}</div>
                  {packet.payloadPreview ? (
                    <div className="mt-1 truncate font-mono text-xs text-slate-500">
                      {packet.payloadPreview}
                    </div>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function endpoint(address?: string, port?: number): string {
  if (!address) {
    return '-';
  }

  return port === undefined ? address : `${address}:${port}`;
}
