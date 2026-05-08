import type {
  DnsDetails,
  HttpDetails,
  InternalDecodedPacket,
  RawPacket,
  TlsDetails,
  TransportProtocol
} from '@/features/analyzer/types';
import { bytesToAscii, bytesToPreview, formatTimestamp } from '@/lib/format';

const ETHER_TYPE_IPV4 = 0x0800;
const ETHER_TYPE_ARP = 0x0806;
const ETHER_TYPE_IPV6 = 0x86dd;
const ETHER_TYPE_VLAN = new Set([0x8100, 0x88a8]);

const TCP_FLAGS: Array<[number, string]> = [
  [0x01, 'FIN'],
  [0x02, 'SYN'],
  [0x04, 'RST'],
  [0x08, 'PSH'],
  [0x10, 'ACK'],
  [0x20, 'URG'],
  [0x40, 'ECE'],
  [0x80, 'CWR']
];

export function decodePacket(packet: RawPacket): InternalDecodedPacket {
  const warnings: string[] = [];
  const base: InternalDecodedPacket = {
    index: packet.index,
    timestampMicros: packet.timestampMicros,
    timestampIso: formatTimestamp(packet.timestampMicros),
    capturedLength: packet.capturedLength,
    originalLength: packet.originalLength,
    linkType: packet.linkType,
    layers: [],
    protocol: 'Unknown',
    summary: 'Unsupported packet',
    payloadPreview: '',
    warnings,
    matchedRuleIds: [],
    payload: new Uint8Array(),
    applicationText: ''
  };

  try {
    if (packet.linkType === 1) {
      return decodeEthernet(packet.data, base);
    }

    if (packet.linkType === 113) {
      return decodeLinuxCooked(packet.data, base);
    }

    if (packet.linkType === 101) {
      return decodeRawIp(packet.data, base);
    }

    warnings.push(`Unsupported link type ${packet.linkType}.`);
    return base;
  } catch (error) {
    warnings.push(error instanceof Error ? error.message : 'Decode failed.');
    return base;
  }
}

function decodeEthernet(data: Uint8Array, base: InternalDecodedPacket): InternalDecodedPacket {
  base.layers.push('Ethernet');

  if (data.byteLength < 14) {
    throw new Error('Ethernet frame is truncated.');
  }

  let etherType = readUint16(data, 12);
  let offset = 14;

  while (ETHER_TYPE_VLAN.has(etherType) && data.byteLength >= offset + 4) {
    base.layers.push('VLAN');
    etherType = readUint16(data, offset + 2);
    offset += 4;
  }

  return decodeEtherType(etherType, data.slice(offset), base);
}

function decodeLinuxCooked(
  data: Uint8Array,
  base: InternalDecodedPacket
): InternalDecodedPacket {
  base.layers.push('SLL');

  if (data.byteLength < 16) {
    throw new Error('Linux cooked header is truncated.');
  }

  const protocol = readUint16(data, 14);
  return decodeEtherType(protocol, data.slice(16), base);
}

function decodeRawIp(data: Uint8Array, base: InternalDecodedPacket): InternalDecodedPacket {
  const version = data[0] >> 4;

  if (version === 4) {
    return decodeIpv4(data, base);
  }

  if (version === 6) {
    return decodeIpv6(data, base);
  }

  base.warnings.push('Raw packet is neither IPv4 nor IPv6.');
  return base;
}

function decodeEtherType(
  etherType: number,
  payload: Uint8Array,
  base: InternalDecodedPacket
): InternalDecodedPacket {
  if (etherType === ETHER_TYPE_IPV4) {
    return decodeIpv4(payload, base);
  }

  if (etherType === ETHER_TYPE_IPV6) {
    return decodeIpv6(payload, base);
  }

  if (etherType === ETHER_TYPE_ARP) {
    base.layers.push('ARP');
    base.protocol = 'ARP';
    base.summary = 'ARP packet';
    base.payload = payload;
    base.payloadPreview = bytesToPreview(payload);
    return base;
  }

  base.protocol = 'Ethernet';
  base.summary = `Ethernet ethertype 0x${etherType.toString(16)}`;
  base.payload = payload;
  base.payloadPreview = bytesToPreview(payload);
  return base;
}

function decodeIpv4(data: Uint8Array, base: InternalDecodedPacket): InternalDecodedPacket {
  base.layers.push('IPv4');
  base.networkProtocol = 'IPv4';

  if (data.byteLength < 20) {
    throw new Error('IPv4 header is truncated.');
  }

  const ihl = (data[0] & 0x0f) * 4;
  const totalLength = Math.min(readUint16(data, 2), data.byteLength);

  if (ihl < 20 || totalLength < ihl) {
    throw new Error('IPv4 header length is invalid.');
  }

  const protocol = data[9];
  base.source = ipv4(data, 12);
  base.destination = ipv4(data, 16);
  const payload = data.slice(ihl, totalLength);

  return decodeTransport(protocol, payload, base);
}

function decodeIpv6(data: Uint8Array, base: InternalDecodedPacket): InternalDecodedPacket {
  base.layers.push('IPv6');
  base.networkProtocol = 'IPv6';

  if (data.byteLength < 40) {
    throw new Error('IPv6 header is truncated.');
  }

  const payloadLength = readUint16(data, 4);
  const nextHeader = data[6];
  base.source = ipv6(data, 8);
  base.destination = ipv6(data, 24);
  const payload = data.slice(40, Math.min(40 + payloadLength, data.byteLength));

  return decodeTransport(nextHeader, payload, base);
}

function decodeTransport(
  protocolNumber: number,
  data: Uint8Array,
  base: InternalDecodedPacket
): InternalDecodedPacket {
  if (protocolNumber === 6) {
    return decodeTcp(data, base);
  }

  if (protocolNumber === 17) {
    return decodeUdp(data, base);
  }

  if (protocolNumber === 1 || protocolNumber === 58) {
    base.layers.push('ICMP');
    base.protocol = 'ICMP';
    base.transportProtocol = 'ICMP';
    base.payload = data;
    base.payloadPreview = bytesToPreview(data);
    base.summary = `${base.source ?? '?'} -> ${base.destination ?? '?'} ICMP`;
    return base;
  }

  const protocolName: TransportProtocol = base.networkProtocol === 'IPv6' ? 'IPv6' : 'IPv4';
  base.protocol = protocolName;
  base.payload = data;
  base.payloadPreview = bytesToPreview(data);
  base.summary = `${base.source ?? '?'} -> ${base.destination ?? '?'} IP protocol ${protocolNumber}`;
  return base;
}

function decodeTcp(data: Uint8Array, base: InternalDecodedPacket): InternalDecodedPacket {
  base.layers.push('TCP');
  base.protocol = 'TCP';
  base.transportProtocol = 'TCP';

  if (data.byteLength < 20) {
    throw new Error('TCP header is truncated.');
  }

  const sourcePort = readUint16(data, 0);
  const destinationPort = readUint16(data, 2);
  const dataOffset = ((data[12] >> 4) & 0x0f) * 4;

  if (dataOffset < 20 || dataOffset > data.byteLength) {
    throw new Error('TCP data offset is invalid.');
  }

  const flagByte = data[13];
  const flags = TCP_FLAGS.filter(([mask]) => (flagByte & mask) !== 0).map(([, label]) => label);
  const payload = data.slice(dataOffset);
  base.sourcePort = sourcePort;
  base.destinationPort = destinationPort;
  base.tcp = {
    flags,
    sequence: readUint32(data, 4),
    acknowledgment: readUint32(data, 8)
  };
  base.payload = payload;
  base.payloadPreview = bytesToPreview(payload);
  base.summary = `${base.source ?? '?'}:${sourcePort} -> ${base.destination ?? '?'}:${destinationPort} TCP ${flags.join(',') || 'segment'}`;

  enrichApplication(payload, base);
  return base;
}

function decodeUdp(data: Uint8Array, base: InternalDecodedPacket): InternalDecodedPacket {
  base.layers.push('UDP');
  base.protocol = 'UDP';
  base.transportProtocol = 'UDP';

  if (data.byteLength < 8) {
    throw new Error('UDP header is truncated.');
  }

  const sourcePort = readUint16(data, 0);
  const destinationPort = readUint16(data, 2);
  const length = Math.min(readUint16(data, 4), data.byteLength);
  const payload = data.slice(8, length);

  base.sourcePort = sourcePort;
  base.destinationPort = destinationPort;
  base.payload = payload;
  base.payloadPreview = bytesToPreview(payload);
  base.summary = `${base.source ?? '?'}:${sourcePort} -> ${base.destination ?? '?'}:${destinationPort} UDP`;

  enrichApplication(payload, base);
  return base;
}

function enrichApplication(payload: Uint8Array, base: InternalDecodedPacket): void {
  base.applicationText = bytesToAscii(payload);

  const dnsPayload =
    base.transportProtocol === 'TCP' && isDnsPort(base) && payload.byteLength > 2
      ? payload.slice(2)
      : payload;

  if (isDnsPort(base)) {
    const dns = parseDns(dnsPayload);
    if (dns) {
      base.layers.push('DNS');
      base.protocol = 'DNS';
      base.dns = dns;
      base.summary = `${base.source ?? '?'}:${base.sourcePort ?? '?'} -> ${base.destination ?? '?'}:${base.destinationPort ?? '?'} DNS ${dns.isResponse ? 'response' : 'query'} ${dns.queryNames.join(', ') || '#' + dns.id}`;
      return;
    }
  }

  const http = parseHttp(payload);
  if (http) {
    base.layers.push('HTTP');
    base.protocol = 'HTTP';
    base.http = http;
    base.summary =
      http.kind === 'request'
        ? `${base.source ?? '?'}:${base.sourcePort ?? '?'} -> ${base.destination ?? '?'}:${base.destinationPort ?? '?'} HTTP ${http.method ?? 'request'} ${http.host ?? ''}`.trim()
        : `${base.source ?? '?'}:${base.sourcePort ?? '?'} -> ${base.destination ?? '?'}:${base.destinationPort ?? '?'} HTTP ${http.statusCode ?? ''}`.trim();
    return;
  }

  const tls = parseTls(payload);
  if (tls) {
    base.layers.push('TLS');
    base.protocol = 'TLS';
    base.tls = tls;
    base.summary = `${base.source ?? '?'}:${base.sourcePort ?? '?'} -> ${base.destination ?? '?'}:${base.destinationPort ?? '?'} TLS ${tls.contentType} ${tls.version}`;
  }
}

function parseDns(payload: Uint8Array): DnsDetails | undefined {
  if (payload.byteLength < 12) {
    return undefined;
  }

  const id = readUint16(payload, 0);
  const flags = readUint16(payload, 2);
  const qdcount = readUint16(payload, 4);
  const ancount = readUint16(payload, 6);
  const queryNames: string[] = [];
  let offset = 12;

  for (let i = 0; i < Math.min(qdcount, 8); i += 1) {
    const result = readDnsName(payload, offset);
    if (!result) {
      break;
    }
    queryNames.push(result.name);
    offset = result.nextOffset + 4;
    if (offset > payload.byteLength) {
      break;
    }
  }

  if (qdcount > 0 && queryNames.length === 0) {
    return undefined;
  }

  return {
    id,
    queryNames,
    answerCount: ancount,
    rcode: flags & 0x0f,
    isResponse: (flags & 0x8000) !== 0
  };
}

function readDnsName(
  payload: Uint8Array,
  offset: number,
  depth = 0
): { name: string; nextOffset: number } | undefined {
  if (depth > 8 || offset >= payload.byteLength) {
    return undefined;
  }

  const labels: string[] = [];
  let cursor = offset;

  while (cursor < payload.byteLength) {
    const length = payload[cursor];

    if (length === 0) {
      return { name: labels.join('.'), nextOffset: cursor + 1 };
    }

    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= payload.byteLength) {
        return undefined;
      }
      const pointer = ((length & 0x3f) << 8) | payload[cursor + 1];
      const pointed = readDnsName(payload, pointer, depth + 1);
      if (!pointed) {
        return undefined;
      }
      labels.push(pointed.name);
      return { name: labels.join('.'), nextOffset: cursor + 2 };
    }

    const labelStart = cursor + 1;
    const labelEnd = labelStart + length;
    if (labelEnd > payload.byteLength) {
      return undefined;
    }
    labels.push(bytesToAscii(payload.slice(labelStart, labelEnd)));
    cursor = labelEnd;
  }

  return undefined;
}

function parseHttp(payload: Uint8Array): HttpDetails | undefined {
  if (payload.byteLength < 4) {
    return undefined;
  }

  const text = bytesToAscii(payload);
  const firstLine = text.split(/\r?\n/, 1)[0] ?? '';
  const requestMatch = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)/.exec(
    firstLine
  );
  const responseMatch = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(firstLine);

  if (!requestMatch && !responseMatch) {
    return undefined;
  }

  const host = /^host:\s*(.+)$/im.exec(text)?.[1]?.trim();

  if (requestMatch) {
    return {
      kind: 'request',
      firstLine,
      method: requestMatch[1],
      host
    };
  }

  return {
    kind: 'response',
    firstLine,
    statusCode: responseMatch ? Number(responseMatch[1]) : undefined,
    host
  };
}

function parseTls(payload: Uint8Array): TlsDetails | undefined {
  if (payload.byteLength < 5) {
    return undefined;
  }

  const contentType = payload[0];
  const major = payload[1];
  const minor = payload[2];
  const length = readUint16(payload, 3);

  if (
    !new Set([20, 21, 22, 23]).has(contentType) ||
    major !== 3 ||
    length > payload.byteLength - 5
  ) {
    return undefined;
  }

  const typeName =
    contentType === 20
      ? 'change_cipher_spec'
      : contentType === 21
        ? 'alert'
        : contentType === 22
          ? 'handshake'
          : 'application_data';

  return {
    contentType: typeName,
    version: `TLS 1.${Math.max(0, minor - 1)}`,
    recordLength: length
  };
}

function isDnsPort(packet: InternalDecodedPacket): boolean {
  return packet.sourcePort === 53 || packet.destinationPort === 53;
}

function ipv4(data: Uint8Array, offset: number): string {
  return `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
}

function ipv6(data: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(readUint16(data, offset + i).toString(16));
  }
  return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}

function readUint16(data: Uint8Array, offset: number): number {
  return (data[offset] << 8) | data[offset + 1];
}

function readUint32(data: Uint8Array, offset: number): number {
  return (
    data[offset] * 2 ** 24 +
    data[offset + 1] * 2 ** 16 +
    data[offset + 2] * 2 ** 8 +
    data[offset + 3]
  );
}
