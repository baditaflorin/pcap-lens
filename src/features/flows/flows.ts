import type {
  FlowEndpoint,
  FlowSummary,
  GraphEdge,
  GraphNode,
  InternalDecodedPacket,
  RuleMatch
} from '@/features/analyzer/types';

interface MutableFlow {
  id: string;
  protocol: string;
  a: FlowEndpoint;
  b: FlowEndpoint;
  packetCount: number;
  byteCount: number;
  firstSeenMicros: number;
  lastSeenMicros: number;
  ruleMatchCount: number;
}

export function buildFlows(
  packets: InternalDecodedPacket[],
  matches: RuleMatch[]
): { flows: FlowSummary[]; nodes: GraphNode[]; edges: GraphEdge[] } {
  const matchCountByPacket = new Map<number, number>();
  for (const match of matches) {
    matchCountByPacket.set(
      match.packetIndex,
      (matchCountByPacket.get(match.packetIndex) ?? 0) + 1
    );
  }

  const flows = new Map<string, MutableFlow>();
  const nodes = new Map<string, GraphNode>();

  for (const packet of packets) {
    if (!packet.source || !packet.destination) {
      continue;
    }

    const protocol = packet.transportProtocol ?? packet.protocol;
    const source = endpoint(packet.source, packet.sourcePort);
    const destination = endpoint(packet.destination, packet.destinationPort);
    const [a, b] = sortEndpoints(source, destination);
    const id = `${protocol}:${a.id}<->${b.id}`;
    const existing = flows.get(id);
    const ruleMatchCount = matchCountByPacket.get(packet.index) ?? 0;

    if (existing) {
      existing.packetCount += 1;
      existing.byteCount += packet.originalLength;
      existing.firstSeenMicros = Math.min(existing.firstSeenMicros, packet.timestampMicros);
      existing.lastSeenMicros = Math.max(existing.lastSeenMicros, packet.timestampMicros);
      existing.ruleMatchCount += ruleMatchCount;
    } else {
      flows.set(id, {
        id,
        protocol,
        a,
        b,
        packetCount: 1,
        byteCount: packet.originalLength,
        firstSeenMicros: packet.timestampMicros,
        lastSeenMicros: packet.timestampMicros,
        ruleMatchCount
      });
    }

    accumulateNode(nodes, source, packet.originalLength);
    accumulateNode(nodes, destination, packet.originalLength);
  }

  const flowList = [...flows.values()].sort((left, right) => right.byteCount - left.byteCount);
  const edgeList = flowList.map((flow): GraphEdge => {
    return {
      id: flow.id,
      source: flow.a.id,
      target: flow.b.id,
      label: flow.protocol,
      packetCount: flow.packetCount,
      byteCount: flow.byteCount,
      ruleMatchCount: flow.ruleMatchCount
    };
  });

  return {
    flows: flowList,
    nodes: [...nodes.values()].sort((left, right) => right.byteCount - left.byteCount),
    edges: edgeList
  };
}

function endpoint(address: string, port?: number): FlowEndpoint {
  return {
    id: port === undefined ? address : `${address}:${port}`,
    address,
    port,
    label: port === undefined ? address : `${address}:${port}`
  };
}

function sortEndpoints(a: FlowEndpoint, b: FlowEndpoint): [FlowEndpoint, FlowEndpoint] {
  return a.id.localeCompare(b.id) <= 0 ? [a, b] : [b, a];
}

function accumulateNode(
  nodes: Map<string, GraphNode>,
  endpointValue: FlowEndpoint,
  bytes: number
): void {
  const existing = nodes.get(endpointValue.id);
  if (existing) {
    existing.packetCount += 1;
    existing.byteCount += bytes;
    return;
  }

  nodes.set(endpointValue.id, {
    id: endpointValue.id,
    label: endpointValue.label,
    packetCount: 1,
    byteCount: bytes
  });
}
