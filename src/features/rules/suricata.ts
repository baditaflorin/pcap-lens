import type {
  InternalDecodedPacket,
  ParsedRule,
  RuleContent,
  RuleFlow,
  RuleMatch,
  RuleParseError
} from '@/features/analyzer/types';
import { bytesToAscii } from '@/lib/format';

/**
 * In-flight TCP-flow state. Keyed by canonicalised 5-tuple. Tracks the
 * direction the original SYN went so we can label `to_server` /
 * `to_client` correctly, and remembers whether the handshake has been
 * seen so `flow:established` rules wait for it.
 */
interface FlowState {
  /** "synSideKey" identifies the side that sent the SYN (= the client). */
  synSideKey: string | null;
  established: boolean;
}

function endpointKey(address: string | undefined, port: number | undefined): string {
  return `${address ?? ''}:${port ?? ''}`;
}

function flowKey(packet: InternalDecodedPacket): string {
  // Canonical 5-tuple: sort the two endpoint keys so A→B and B→A both
  // resolve to the same flow.
  const a = endpointKey(packet.source, packet.sourcePort);
  const b = endpointKey(packet.destination, packet.destinationPort);
  const protocol = packet.transportProtocol ?? 'IP';
  return a < b ? `${protocol}|${a}|${b}` : `${protocol}|${b}|${a}`;
}

function updateFlowState(packet: InternalDecodedPacket, state: FlowState): void {
  if (packet.transportProtocol !== 'TCP' || !packet.tcp) {
    // UDP/ICMP have no handshake — treat the first packet as
    // establishing the flow direction and the second onwards as
    // "established", which matches Suricata's bidirectional flow
    // tracking for stateless protocols.
    if (!state.synSideKey) {
      state.synSideKey = endpointKey(packet.source, packet.sourcePort);
    } else if (!state.established) {
      state.established = true;
    }
    return;
  }
  const flags = packet.tcp.flags.map((f) => f.toUpperCase());
  const hasSyn = flags.includes('SYN');
  const hasAck = flags.includes('ACK');
  const sideKey = endpointKey(packet.source, packet.sourcePort);

  if (hasSyn && !hasAck && !state.synSideKey) {
    // First SYN — record the client side.
    state.synSideKey = sideKey;
  } else if (hasSyn && hasAck && state.synSideKey && state.synSideKey !== sideKey) {
    // SYN/ACK from the other side completes step 2 of the handshake.
    // The next packet from the client (the final ACK) will fully
    // establish, but we mark established here too — Suricata considers
    // flow:established true after the SYN/ACK is observed because the
    // server has accepted the connection.
    state.established = true;
  } else if (!hasSyn && state.synSideKey) {
    // Any post-SYN packet on the flow means we've moved past handshake.
    state.established = true;
  }
}

function packetDirection(
  packet: InternalDecodedPacket,
  state: FlowState
): 'to_server' | 'to_client' | 'unknown' {
  if (!state.synSideKey) return 'unknown';
  const sideKey = endpointKey(packet.source, packet.sourcePort);
  return sideKey === state.synSideKey ? 'to_server' : 'to_client';
}

export function parseFlowOption(value: string): RuleFlow {
  const flow: RuleFlow = {};
  for (const part of value.split(',').map((s) => s.trim().toLowerCase())) {
    if (part === 'established') flow.established = true;
    else if (part === 'to_server' || part === 'from_client') flow.toServer = true;
    else if (part === 'to_client' || part === 'from_server') flow.toClient = true;
    // 'stateless' / 'no_state' explicitly opt out — leave the flow
    // object empty so the matcher behaves as before. Unknown options
    // are ignored rather than failing the rule (forward compat with
    // Suricata's longer list).
  }
  return flow;
}

const HEADER_RE =
  /^\s*(alert|drop|pass|log|reject)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$/i;

export const DEFAULT_RULES = `# v1 Suricata-style subset: action proto src src_port -> dst dst_port (options)
# Supported options: msg, content, nocase, sid, rev, classtype, flow.
# Supported flow keywords: established, to_server, to_client.
alert http any any -> any any (msg:"HTTP request observed"; content:"GET"; nocase; sid:1000001; rev:1;)
alert dns any any -> any any (msg:"DNS lookup observed"; sid:1000002; rev:1;)
alert dns any any -> any any (msg:"DNS query references example"; content:"example"; nocase; sid:1000003; rev:1;)
alert tls any any -> any 443 (msg:"TLS record on 443"; sid:1000004; rev:1;)
alert tcp any any -> any 80 (msg:"Plain HTTP destination port"; sid:1000005; rev:1;)
# Stateful example — only fires once a TCP handshake has been observed
# AND the packet is travelling from the client side to the server side:
# alert tcp any any -> any 443 (msg:"Outbound TLS data"; flow:established,to_server; sid:1000006; rev:1;)`;

export function parseRules(text: string): { rules: ParsedRule[]; errors: RuleParseError[] } {
  const rules: ParsedRule[] = [];
  const errors: RuleParseError[] = [];

  text.split(/\r?\n/).forEach((lineText, index) => {
    const line = index + 1;
    const raw = lineText.trim();

    if (!raw || raw.startsWith('#')) {
      return;
    }

    const match = HEADER_RE.exec(raw);
    if (!match) {
      errors.push({
        line,
        raw: lineText,
        message: 'Rule header does not match the v1 subset.'
      });
      return;
    }

    const [
      ,
      action,
      protocol,
      sourceAddress,
      sourcePort,
      direction,
      destinationAddress,
      destinationPort,
      body
    ] = match;
    const options = parseOptions(body);
    const msg = firstOption(options, 'msg') ?? `Rule on line ${line}`;
    const sid = firstOption(options, 'sid') ?? `line-${line}`;
    const contents = contentOptions(options);

    const flowRaw = firstOption(options, 'flow');
    const flow = flowRaw ? parseFlowOption(flowRaw) : undefined;

    rules.push({
      id: sid,
      line,
      action: action.toLowerCase(),
      protocol: protocol.toLowerCase(),
      sourceAddress,
      sourcePort,
      direction: direction as '->' | '<>',
      destinationAddress,
      destinationPort,
      message: msg,
      sid,
      rev: firstOption(options, 'rev'),
      classtype: firstOption(options, 'classtype'),
      contents,
      flow,
      raw
    });
  });

  return { rules, errors };
}

export function matchRules(packets: InternalDecodedPacket[], rules: ParsedRule[]): RuleMatch[] {
  const matches: RuleMatch[] = [];
  // Per-flow state computed by walking packets in capture order. The
  // map is local to this call so re-running matchRules with a fresh
  // rule set (e.g. after the user edits the rule textarea) doesn't
  // accidentally remember handshakes from a previous run.
  const flowStates = new Map<string, FlowState>();

  for (const packet of packets) {
    const key = flowKey(packet);
    let flowState = flowStates.get(key);
    if (!flowState) {
      flowState = { synSideKey: null, established: false };
      flowStates.set(key, flowState);
    }
    updateFlowState(packet, flowState);

    const packetMatches: string[] = [];

    for (const rule of rules) {
      if (matchesRule(packet, rule, flowState)) {
        packetMatches.push(rule.id);
        matches.push({
          id: `${rule.id}-${packet.index}`,
          packetIndex: packet.index,
          ruleId: rule.id,
          sid: rule.sid,
          message: rule.message,
          action: rule.action,
          protocol: rule.protocol,
          summary: packet.summary
        });
      }
    }

    packet.matchedRuleIds = packetMatches;
  }

  return matches;
}

function matchesFlow(
  packet: InternalDecodedPacket,
  rule: ParsedRule,
  flowState: FlowState
): boolean {
  if (!rule.flow) return true;
  if (rule.flow.established && !flowState.established) {
    // For a stateful rule, the very first packet on a flow can't have
    // observed the handshake yet — wait for the next one.
    return false;
  }
  if (rule.flow.toServer || rule.flow.toClient) {
    const direction = packetDirection(packet, flowState);
    if (rule.flow.toServer && direction !== 'to_server') return false;
    if (rule.flow.toClient && direction !== 'to_client') return false;
  }
  return true;
}

function matchesRule(
  packet: InternalDecodedPacket,
  rule: ParsedRule,
  flowState: FlowState
): boolean {
  if (!matchesFlow(packet, rule, flowState)) {
    return false;
  }
  if (!matchesProtocol(packet, rule.protocol)) {
    return false;
  }

  if (rule.direction === '<>') {
    if (
      !(
        matchesEndpoint(
          packet.source,
          packet.sourcePort,
          rule.sourceAddress,
          rule.sourcePort
        ) &&
        matchesEndpoint(
          packet.destination,
          packet.destinationPort,
          rule.destinationAddress,
          rule.destinationPort
        )
      ) &&
      !(
        matchesEndpoint(
          packet.destination,
          packet.destinationPort,
          rule.sourceAddress,
          rule.sourcePort
        ) &&
        matchesEndpoint(
          packet.source,
          packet.sourcePort,
          rule.destinationAddress,
          rule.destinationPort
        )
      )
    ) {
      return false;
    }
  } else if (
    !matchesEndpoint(packet.source, packet.sourcePort, rule.sourceAddress, rule.sourcePort) ||
    !matchesEndpoint(
      packet.destination,
      packet.destinationPort,
      rule.destinationAddress,
      rule.destinationPort
    )
  ) {
    return false;
  }

  return rule.contents.every((content) => packetContains(packet, content));
}

function matchesProtocol(packet: InternalDecodedPacket, protocol: string): boolean {
  if (protocol === 'any' || protocol === 'ip') {
    return Boolean(packet.networkProtocol);
  }

  if (protocol === 'tcp' || protocol === 'udp' || protocol === 'icmp') {
    return packet.transportProtocol?.toLowerCase() === protocol;
  }

  return (
    packet.protocol.toLowerCase() === protocol ||
    packet.layers.some((layer) => layer.toLowerCase() === protocol)
  );
}

function matchesEndpoint(
  address: string | undefined,
  port: number | undefined,
  addressRule: string,
  portRule: string
): boolean {
  if (!matchesAddress(address, addressRule)) {
    return false;
  }

  return matchesPort(port, portRule);
}

function matchesAddress(address: string | undefined, rule: string): boolean {
  if (rule.toLowerCase() === 'any') {
    return true;
  }

  return address === rule;
}

function matchesPort(port: number | undefined, rule: string): boolean {
  if (rule.toLowerCase() === 'any') {
    return true;
  }

  const normalized = rule.replace(/^\[/, '').replace(/\]$/, '');
  const allowed = normalized.split(',').map((part) => Number(part.trim()));

  return port !== undefined && allowed.includes(port);
}

function packetContains(packet: InternalDecodedPacket, content: RuleContent): boolean {
  if (content.bytes.byteLength === 0) {
    return true;
  }

  if (content.nocase) {
    const haystack =
      `${bytesToAscii(packet.payload)} ${packet.applicationText} ${packet.summary}`.toLowerCase();
    return haystack.includes(content.text.toLowerCase());
  }

  return (
    indexOfBytes(packet.payload, content.bytes) >= 0 ||
    packet.applicationText.includes(content.text)
  );
}

function parseOptions(body: string): Array<{ key: string; value?: string }> {
  return splitOptionBody(body).map((option) => {
    const separator = option.indexOf(':');

    if (separator === -1) {
      return { key: option.trim().toLowerCase() };
    }

    return {
      key: option.slice(0, separator).trim().toLowerCase(),
      value: unquote(option.slice(separator + 1).trim())
    };
  });
}

function splitOptionBody(body: string): string[] {
  const parts: string[] = [];
  let current = '';
  let inQuote = false;
  let escaped = false;

  for (const char of body) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === '\\') {
      current += char;
      escaped = true;
      continue;
    }

    if (char === '"') {
      inQuote = !inQuote;
      current += char;
      continue;
    }

    if (char === ';' && !inQuote) {
      if (current.trim()) {
        parts.push(current.trim());
      }
      current = '';
      continue;
    }

    current += char;
  }

  if (current.trim()) {
    parts.push(current.trim());
  }

  return parts;
}

function firstOption(
  options: Array<{ key: string; value?: string }>,
  key: string
): string | undefined {
  return options.find((option) => option.key === key)?.value;
}

function contentOptions(options: Array<{ key: string; value?: string }>): RuleContent[] {
  const contents: RuleContent[] = [];

  for (const option of options) {
    if (option.key === 'content' && option.value !== undefined) {
      contents.push(toContent(option.value));
      continue;
    }

    if (option.key === 'nocase' && contents.length > 0) {
      contents[contents.length - 1] = { ...contents[contents.length - 1], nocase: true };
    }
  }

  return contents;
}

function toContent(value: string): RuleContent {
  const bytes: number[] = [];
  let text = '';
  let i = 0;

  while (i < value.length) {
    if (value[i] === '|' && value.indexOf('|', i + 1) !== -1) {
      const end = value.indexOf('|', i + 1);
      const hex = value.slice(i + 1, end).trim();
      for (const part of hex.split(/\s+/)) {
        if (/^[0-9a-f]{2}$/i.test(part)) {
          const byte = Number.parseInt(part, 16);
          bytes.push(byte);
          text += String.fromCharCode(byte);
        }
      }
      i = end + 1;
      continue;
    }

    const char = value[i];
    const next = value[i + 1];
    if (char === '\\' && next) {
      const decoded = next === 'r' ? '\r' : next === 'n' ? '\n' : next === 't' ? '\t' : next;
      bytes.push(decoded.charCodeAt(0));
      text += decoded;
      i += 2;
      continue;
    }

    bytes.push(char.charCodeAt(0));
    text += char;
    i += 1;
  }

  return {
    text,
    bytes: new Uint8Array(bytes),
    nocase: false
  };
}

function unquote(value: string): string {
  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }

  return value;
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.byteLength === 0) {
    return 0;
  }

  outer: for (let i = 0; i <= haystack.byteLength - needle.byteLength; i += 1) {
    for (let j = 0; j < needle.byteLength; j += 1) {
      if (haystack[i + j] !== needle[j]) {
        continue outer;
      }
    }
    return i;
  }

  return -1;
}
