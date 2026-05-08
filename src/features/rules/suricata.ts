import type {
  InternalDecodedPacket,
  ParsedRule,
  RuleContent,
  RuleMatch,
  RuleParseError
} from '@/features/analyzer/types';
import { bytesToAscii } from '@/lib/format';

const HEADER_RE =
  /^\s*(alert|drop|pass|log|reject)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$/i;

export const DEFAULT_RULES = `# v1 Suricata-style subset: action proto src src_port -> dst dst_port (options)
alert http any any -> any any (msg:"HTTP request observed"; content:"GET"; nocase; sid:1000001; rev:1;)
alert dns any any -> any any (msg:"DNS lookup observed"; sid:1000002; rev:1;)
alert dns any any -> any any (msg:"DNS query references example"; content:"example"; nocase; sid:1000003; rev:1;)
alert tls any any -> any 443 (msg:"TLS record on 443"; sid:1000004; rev:1;)
alert tcp any any -> any 80 (msg:"Plain HTTP destination port"; sid:1000005; rev:1;)`;

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
      raw
    });
  });

  return { rules, errors };
}

export function matchRules(packets: InternalDecodedPacket[], rules: ParsedRule[]): RuleMatch[] {
  const matches: RuleMatch[] = [];

  for (const packet of packets) {
    const packetMatches: string[] = [];

    for (const rule of rules) {
      if (matchesRule(packet, rule)) {
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

function matchesRule(packet: InternalDecodedPacket, rule: ParsedRule): boolean {
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
