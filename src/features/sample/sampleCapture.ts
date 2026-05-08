export function createSampleCapture(): ArrayBuffer {
  const packets = [
    ethernet(
      ipv4(
        [10, 0, 0, 5],
        [93, 184, 216, 34],
        6,
        tcp(
          49152,
          80,
          1,
          0,
          0x18,
          ascii('GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: pcap-lens\r\n\r\n')
        )
      )
    ),
    ethernet(
      ipv4(
        [93, 184, 216, 34],
        [10, 0, 0, 5],
        6,
        tcp(
          80,
          49152,
          1,
          58,
          0x18,
          ascii('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok')
        )
      )
    ),
    ethernet(
      ipv4([10, 0, 0, 5], [8, 8, 8, 8], 17, udp(53000, 53, dnsQuery('example.org', 0x1200)))
    ),
    ethernet(
      ipv4(
        [8, 8, 8, 8],
        [10, 0, 0, 5],
        17,
        udp(53, 53000, dnsResponse('example.org', 0x1200, [93, 184, 216, 34]))
      )
    ),
    ethernet(
      ipv4([10, 0, 0, 5], [140, 82, 112, 4], 6, tcp(49153, 443, 10, 0, 0x18, tlsClientHello()))
    )
  ];

  const records = packets.map((packet, index) =>
    pcapRecord(packet, 1_720_000_000 + index, index * 1000)
  );
  const output = concat([pcapHeader(), ...records]);
  const buffer = new ArrayBuffer(output.byteLength);
  new Uint8Array(buffer).set(output);
  return buffer;
}

function pcapHeader(): Uint8Array {
  const header = new Uint8Array(24);
  const view = new DataView(header.buffer);
  header.set([0xd4, 0xc3, 0xb2, 0xa1], 0);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setInt32(8, 0, true);
  view.setUint32(12, 0, true);
  view.setUint32(16, 65_535, true);
  view.setUint32(20, 1, true);
  return header;
}

function pcapRecord(packet: Uint8Array, seconds: number, micros: number): Uint8Array {
  const record = new Uint8Array(16 + packet.byteLength);
  const view = new DataView(record.buffer);
  view.setUint32(0, seconds, true);
  view.setUint32(4, micros, true);
  view.setUint32(8, packet.byteLength, true);
  view.setUint32(12, packet.byteLength, true);
  record.set(packet, 16);
  return record;
}

function ethernet(payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(14 + payload.byteLength);
  frame.set([0x10, 0x22, 0x33, 0x44, 0x55, 0x66], 0);
  frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
  writeUint16(frame, 12, 0x0800);
  frame.set(payload, 14);
  return frame;
}

function ipv4(src: number[], dst: number[], protocol: number, payload: Uint8Array): Uint8Array {
  const packet = new Uint8Array(20 + payload.byteLength);
  packet[0] = 0x45;
  packet[1] = 0;
  writeUint16(packet, 2, packet.byteLength);
  writeUint16(packet, 4, 1);
  writeUint16(packet, 6, 0x4000);
  packet[8] = 64;
  packet[9] = protocol;
  packet.set(src, 12);
  packet.set(dst, 16);
  packet.set(payload, 20);
  writeUint16(packet, 10, ipv4Checksum(packet.slice(0, 20)));
  return packet;
}

function tcp(
  srcPort: number,
  dstPort: number,
  seq: number,
  ack: number,
  flags: number,
  payload: Uint8Array
): Uint8Array {
  const segment = new Uint8Array(20 + payload.byteLength);
  writeUint16(segment, 0, srcPort);
  writeUint16(segment, 2, dstPort);
  writeUint32(segment, 4, seq);
  writeUint32(segment, 8, ack);
  segment[12] = 0x50;
  segment[13] = flags;
  writeUint16(segment, 14, 64_240);
  segment.set(payload, 20);
  return segment;
}

function udp(srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const datagram = new Uint8Array(8 + payload.byteLength);
  writeUint16(datagram, 0, srcPort);
  writeUint16(datagram, 2, dstPort);
  writeUint16(datagram, 4, datagram.byteLength);
  datagram.set(payload, 8);
  return datagram;
}

function dnsQuery(name: string, id: number): Uint8Array {
  const encodedName = dnsName(name);
  const packet = new Uint8Array(12 + encodedName.byteLength + 4);
  writeUint16(packet, 0, id);
  writeUint16(packet, 2, 0x0100);
  writeUint16(packet, 4, 1);
  packet.set(encodedName, 12);
  writeUint16(packet, 12 + encodedName.byteLength, 1);
  writeUint16(packet, 12 + encodedName.byteLength + 2, 1);
  return packet;
}

function dnsResponse(name: string, id: number, address: number[]): Uint8Array {
  const query = dnsQuery(name, id);
  const encodedName = dnsName(name);
  const answerOffset = query.byteLength;
  const packet = new Uint8Array(query.byteLength + encodedName.byteLength + 16);
  packet.set(query);
  writeUint16(packet, 2, 0x8180);
  writeUint16(packet, 6, 1);
  packet.set(encodedName, answerOffset);
  let cursor = answerOffset + encodedName.byteLength;
  writeUint16(packet, cursor, 1);
  cursor += 2;
  writeUint16(packet, cursor, 1);
  cursor += 2;
  writeUint32(packet, cursor, 300);
  cursor += 4;
  writeUint16(packet, cursor, 4);
  cursor += 2;
  packet.set(address, cursor);
  return packet;
}

function dnsName(name: string): Uint8Array {
  const labels = name.split('.');
  const bytes: number[] = [];

  for (const label of labels) {
    bytes.push(label.length, ...ascii(label));
  }

  bytes.push(0);
  return new Uint8Array(bytes);
}

function tlsClientHello(): Uint8Array {
  return new Uint8Array([0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00]);
}

function ascii(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return output;
}

function writeUint16(data: Uint8Array, offset: number, value: number): void {
  data[offset] = (value >> 8) & 0xff;
  data[offset + 1] = value & 0xff;
}

function writeUint32(data: Uint8Array, offset: number, value: number): void {
  data[offset] = (value >> 24) & 0xff;
  data[offset + 1] = (value >> 16) & 0xff;
  data[offset + 2] = (value >> 8) & 0xff;
  data[offset + 3] = value & 0xff;
}

function ipv4Checksum(header: Uint8Array): number {
  let sum = 0;

  for (let i = 0; i < header.byteLength; i += 2) {
    sum += (header[i] << 8) + header[i + 1];
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum & 0xffff;
}
