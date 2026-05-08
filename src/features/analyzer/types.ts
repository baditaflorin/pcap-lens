export type CaptureFormat = 'pcap' | 'pcapng';

export type LinkType = 1 | 101 | 113 | number;

export type TransportProtocol =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'IPv4'
  | 'IPv6'
  | 'ARP'
  | 'Ethernet'
  | 'Unknown';

export interface RawPacket {
  index: number;
  timestampMicros: number;
  capturedLength: number;
  originalLength: number;
  linkType: LinkType;
  data: Uint8Array;
}

export interface ParsedCapture {
  format: CaptureFormat;
  endian: 'little' | 'big';
  snapLength: number;
  linkType: LinkType;
  packets: RawPacket[];
  warnings: string[];
}

export interface TcpDetails {
  flags: string[];
  sequence: number;
  acknowledgment: number;
}

export interface DnsDetails {
  id: number;
  queryNames: string[];
  answerCount: number;
  rcode: number;
  isResponse: boolean;
}

export interface HttpDetails {
  kind: 'request' | 'response';
  firstLine: string;
  method?: string;
  statusCode?: number;
  host?: string;
}

export interface TlsDetails {
  contentType: string;
  version: string;
  recordLength: number;
}

export interface DecodedPacket {
  index: number;
  timestampMicros: number;
  timestampIso: string;
  capturedLength: number;
  originalLength: number;
  linkType: LinkType;
  layers: string[];
  protocol: TransportProtocol | 'DNS' | 'HTTP' | 'TLS';
  source?: string;
  destination?: string;
  sourcePort?: number;
  destinationPort?: number;
  summary: string;
  payloadPreview: string;
  warnings: string[];
  tcp?: TcpDetails;
  dns?: DnsDetails;
  http?: HttpDetails;
  tls?: TlsDetails;
  matchedRuleIds: string[];
}

export interface InternalDecodedPacket extends DecodedPacket {
  networkProtocol?: 'IPv4' | 'IPv6';
  transportProtocol?: 'TCP' | 'UDP' | 'ICMP';
  payload: Uint8Array;
  applicationText: string;
}

export interface FlowEndpoint {
  id: string;
  address: string;
  port?: number;
  label: string;
}

export interface FlowSummary {
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

export interface GraphNode {
  id: string;
  label: string;
  packetCount: number;
  byteCount: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  packetCount: number;
  byteCount: number;
  ruleMatchCount: number;
}

export interface ParsedRule {
  id: string;
  line: number;
  action: string;
  protocol: string;
  sourceAddress: string;
  sourcePort: string;
  direction: '->' | '<>';
  destinationAddress: string;
  destinationPort: string;
  message: string;
  sid: string;
  rev?: string;
  classtype?: string;
  contents: RuleContent[];
  raw: string;
}

export interface RuleContent {
  text: string;
  bytes: Uint8Array;
  nocase: boolean;
}

export interface RuleParseError {
  line: number;
  message: string;
  raw: string;
}

export interface RuleMatch {
  id: string;
  packetIndex: number;
  ruleId: string;
  sid: string;
  message: string;
  action: string;
  protocol: string;
  summary: string;
}

export interface CaptureSummary {
  fileName: string;
  format: CaptureFormat;
  packetCount: number;
  decodedPacketCount: number;
  flowCount: number;
  ruleMatchCount: number;
  firstPacketIso?: string;
  lastPacketIso?: string;
  totalBytes: number;
  warnings: string[];
}

export interface ProtocolCount {
  protocol: string;
  packets: number;
  bytes: number;
}

export interface AnalysisResult {
  schemaVersion: 'analysis.v1';
  summary: CaptureSummary;
  packets: DecodedPacket[];
  flows: FlowSummary[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  protocolCounts: ProtocolCount[];
  rules: {
    parsed: ParsedRule[];
    errors: RuleParseError[];
    matches: RuleMatch[];
  };
}
