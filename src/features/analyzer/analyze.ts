import { parseCapture } from '@/features/capture/pcap';
import { buildFlows } from '@/features/flows/flows';
import { decodePacket } from '@/features/protocols/decoder';
import { DEFAULT_RULES, matchRules, parseRules } from '@/features/rules/suricata';
import type {
  AnalysisResult,
  DecodedPacket,
  InternalDecodedPacket,
  ProtocolCount
} from './types';

export function analyzeCapture(
  buffer: ArrayBuffer | Uint8Array,
  fileName: string,
  rulesText = DEFAULT_RULES
): AnalysisResult {
  const capture = parseCapture(buffer);
  const decoded = capture.packets.map((packet) => decodePacket(packet));
  const parsedRules = parseRules(rulesText);
  const matches = matchRules(decoded, parsedRules.rules);
  const graph = buildFlows(decoded, matches);
  const packets = decoded.map(toPublicPacket);
  const packetTimes = decoded
    .map((packet) => packet.timestampMicros)
    .filter((timestamp) => Number.isFinite(timestamp) && timestamp > 0);
  const totalBytes = capture.packets.reduce((sum, packet) => sum + packet.originalLength, 0);

  return {
    schemaVersion: 'analysis.v1',
    summary: {
      fileName,
      format: capture.format,
      packetCount: capture.packets.length,
      decodedPacketCount: decoded.filter((packet) => packet.protocol !== 'Unknown').length,
      flowCount: graph.flows.length,
      ruleMatchCount: matches.length,
      firstPacketIso:
        packetTimes.length > 0
          ? new Date(Math.min(...packetTimes) / 1000).toISOString()
          : undefined,
      lastPacketIso:
        packetTimes.length > 0
          ? new Date(Math.max(...packetTimes) / 1000).toISOString()
          : undefined,
      totalBytes,
      warnings: capture.warnings
    },
    packets,
    flows: graph.flows,
    graph: {
      nodes: graph.nodes,
      edges: graph.edges
    },
    protocolCounts: protocolCounts(decoded),
    rules: {
      parsed: parsedRules.rules,
      errors: parsedRules.errors,
      matches
    }
  };
}

function toPublicPacket(packet: InternalDecodedPacket): DecodedPacket {
  return {
    index: packet.index,
    timestampMicros: packet.timestampMicros,
    timestampIso: packet.timestampIso,
    capturedLength: packet.capturedLength,
    originalLength: packet.originalLength,
    linkType: packet.linkType,
    layers: packet.layers,
    protocol: packet.protocol,
    source: packet.source,
    destination: packet.destination,
    sourcePort: packet.sourcePort,
    destinationPort: packet.destinationPort,
    summary: packet.summary,
    payloadPreview: packet.payloadPreview,
    warnings: packet.warnings,
    tcp: packet.tcp,
    dns: packet.dns,
    http: packet.http,
    tls: packet.tls,
    matchedRuleIds: packet.matchedRuleIds
  };
}

function protocolCounts(packets: InternalDecodedPacket[]): ProtocolCount[] {
  const counts = new Map<string, ProtocolCount>();

  for (const packet of packets) {
    const protocol = packet.protocol;
    const current = counts.get(protocol) ?? { protocol, packets: 0, bytes: 0 };
    current.packets += 1;
    current.bytes += packet.originalLength;
    counts.set(protocol, current);
  }

  return [...counts.values()].sort((left, right) => right.packets - left.packets);
}
