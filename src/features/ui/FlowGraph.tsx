import type { GraphEdge, GraphNode } from '@/features/analyzer/types';
import { formatBytes } from '@/lib/format';

interface FlowGraphProps {
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
}

export function FlowGraph({ graph }: FlowGraphProps) {
  const nodes = graph.nodes.slice(0, 16);
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
    .slice(0, 32);
  const positions = layout(nodes);

  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="section-title">Flow Graph</h2>
        <span className="text-sm text-slate-500">{graph.edges.length} edges</span>
      </div>

      <svg
        className="mt-4 aspect-[16/10] w-full rounded-lg bg-slate-950"
        viewBox="0 0 900 560"
        role="img"
      >
        <title>Packet flow graph</title>
        {edges.map((edge) => {
          const source = positions.get(edge.source);
          const target = positions.get(edge.target);

          if (!source || !target) {
            return null;
          }

          return (
            <g key={edge.id}>
              <line
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={edge.ruleMatchCount > 0 ? '#f59e0b' : '#5eead4'}
                strokeOpacity={0.72}
                strokeWidth={Math.min(9, 1.5 + Math.log2(edge.packetCount + 1))}
              />
              <title>
                {edge.label}: {edge.packetCount} packets, {formatBytes(edge.byteCount)}
              </title>
            </g>
          );
        })}

        {nodes.map((node) => {
          const position = positions.get(node.id);
          if (!position) {
            return null;
          }

          return (
            <g key={node.id} transform={`translate(${position.x} ${position.y})`}>
              <circle
                r={Math.min(34, 16 + Math.log2(node.packetCount + 1) * 4)}
                fill="#f8fafc"
              />
              <circle r={5} fill="#0f766e" />
              <text
                y={46}
                textAnchor="middle"
                fill="#f8fafc"
                fontSize="18"
                fontFamily="ui-monospace, SFMono-Regular, monospace"
              >
                {shortLabel(node.label)}
              </text>
              <title>
                {node.label}: {node.packetCount} packets, {formatBytes(node.byteCount)}
              </title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function layout(nodes: GraphNode[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  const centerX = 450;
  const centerY = 270;
  const radius = nodes.length <= 4 ? 160 : 215;

  nodes.forEach((node, index) => {
    const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2 - Math.PI / 2;
    positions.set(node.id, {
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius
    });
  });

  return positions;
}

function shortLabel(label: string): string {
  return label.length > 20 ? `${label.slice(0, 18)}...` : label;
}
