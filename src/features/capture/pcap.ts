import { AnalysisError } from '@/lib/errors';
import type { LinkType, ParsedCapture, RawPacket } from '@/features/analyzer/types';

interface ClassicMagic {
  endian: 'little' | 'big';
  resolution: 'micro' | 'nano';
}

const PCAP_MAGIC: Record<string, ClassicMagic> = {
  d4c3b2a1: { endian: 'little', resolution: 'micro' },
  a1b2c3d4: { endian: 'big', resolution: 'micro' },
  '4d3cb2a1': { endian: 'little', resolution: 'nano' },
  a1b23c4d: { endian: 'big', resolution: 'nano' }
};

const PCAPNG_SECTION = 0x0a0d0d0a;
const PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d;

export function parseCapture(buffer: ArrayBuffer | Uint8Array): ParsedCapture {
  const data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  if (data.byteLength < 4) {
    throw new AnalysisError('Capture is too small to contain a file header.', 'capture parser');
  }

  const magic = [...data.slice(0, 4)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

  if (magic in PCAP_MAGIC) {
    return parseClassicPcap(data, PCAP_MAGIC[magic]);
  }

  const view = viewFor(data);
  if (view.getUint32(0, false) === PCAPNG_SECTION) {
    return parsePcapNg(data);
  }

  throw new AnalysisError(
    'Unsupported file format. Expected PCAP or PCAPNG.',
    'capture parser'
  );
}

function parseClassicPcap(data: Uint8Array, magic: ClassicMagic): ParsedCapture {
  if (data.byteLength < 24) {
    throw new AnalysisError('Classic PCAP header is truncated.', 'capture parser');
  }

  const view = viewFor(data);
  const little = magic.endian === 'little';
  const snapLength = view.getUint32(16, little);
  const linkType = view.getUint32(20, little) as LinkType;
  const packets: RawPacket[] = [];
  const warnings: string[] = [];
  let offset = 24;
  let index = 1;

  while (offset + 16 <= data.byteLength) {
    const tsSec = view.getUint32(offset, little);
    const tsFrac = view.getUint32(offset + 4, little);
    const capturedLength = view.getUint32(offset + 8, little);
    const originalLength = view.getUint32(offset + 12, little);
    offset += 16;

    if (capturedLength > data.byteLength - offset) {
      warnings.push(`Packet ${index} is truncated and was skipped.`);
      break;
    }

    const timestampMicros =
      tsSec * 1_000_000 + (magic.resolution === 'nano' ? Math.floor(tsFrac / 1000) : tsFrac);

    packets.push({
      index,
      timestampMicros,
      capturedLength,
      originalLength,
      linkType,
      data: data.slice(offset, offset + capturedLength)
    });

    offset += capturedLength;
    index += 1;
  }

  if (offset < data.byteLength) {
    warnings.push('Trailing bytes after the final packet were ignored.');
  }

  return {
    format: 'pcap',
    endian: magic.endian,
    snapLength,
    linkType,
    packets,
    warnings
  };
}

function parsePcapNg(data: Uint8Array): ParsedCapture {
  const view = viewFor(data);
  const interfaces: LinkType[] = [];
  const packets: RawPacket[] = [];
  const warnings: string[] = [];
  let offset = 0;
  let endian: 'little' | 'big' = 'little';
  let sectionSeen = false;
  let index = 1;

  while (offset + 12 <= data.byteLength) {
    const blockType = view.getUint32(offset, endian === 'little');

    if (!sectionSeen) {
      if (view.getUint32(offset, false) !== PCAPNG_SECTION) {
        throw new AnalysisError(
          'PCAPNG does not start with a section header block.',
          'capture parser'
        );
      }

      const littleBom = view.getUint32(offset + 8, true);
      const bigBom = view.getUint32(offset + 8, false);
      if (littleBom === PCAPNG_BYTE_ORDER_MAGIC) {
        endian = 'little';
      } else if (bigBom === PCAPNG_BYTE_ORDER_MAGIC) {
        endian = 'big';
      } else {
        throw new AnalysisError('PCAPNG byte-order magic is invalid.', 'capture parser');
      }
      sectionSeen = true;
    } else if (blockType === PCAPNG_SECTION) {
      const littleBom = view.getUint32(offset + 8, true);
      endian = littleBom === PCAPNG_BYTE_ORDER_MAGIC ? 'little' : 'big';
    }

    const little = endian === 'little';
    const normalizedBlockType = view.getUint32(offset, little);
    const blockLength = view.getUint32(offset + 4, little);

    if (blockLength < 12 || offset + blockLength > data.byteLength) {
      warnings.push(`Invalid PCAPNG block length at byte ${offset}; parsing stopped.`);
      break;
    }

    const bodyOffset = offset + 8;
    const bodyLength = blockLength - 12;

    if (normalizedBlockType === 1 && bodyLength >= 8) {
      interfaces.push(view.getUint16(bodyOffset, little) as LinkType);
    }

    if (normalizedBlockType === 6 && bodyLength >= 20) {
      const interfaceId = view.getUint32(bodyOffset, little);
      const timestampHigh = view.getUint32(bodyOffset + 4, little);
      const timestampLow = view.getUint32(bodyOffset + 8, little);
      const capturedLength = view.getUint32(bodyOffset + 12, little);
      const originalLength = view.getUint32(bodyOffset + 16, little);
      const packetOffset = bodyOffset + 20;

      if (capturedLength <= bodyLength - 20) {
        const timestampMicros = timestampHigh * 2 ** 32 + timestampLow;
        packets.push({
          index,
          timestampMicros,
          capturedLength,
          originalLength,
          linkType: interfaces[interfaceId] ?? 1,
          data: data.slice(packetOffset, packetOffset + capturedLength)
        });
        index += 1;
      } else {
        warnings.push(`Enhanced packet block ${index} is truncated and was skipped.`);
      }
    }

    if (normalizedBlockType === 3 && bodyLength >= 4) {
      const originalLength = view.getUint32(bodyOffset, little);
      const capturedLength = Math.min(originalLength, bodyLength - 4);
      packets.push({
        index,
        timestampMicros: 0,
        capturedLength,
        originalLength,
        linkType: interfaces[0] ?? 1,
        data: data.slice(bodyOffset + 4, bodyOffset + 4 + capturedLength)
      });
      index += 1;
    }

    offset += blockLength;
  }

  return {
    format: 'pcapng',
    endian,
    snapLength: 0,
    linkType: interfaces[0] ?? 1,
    packets,
    warnings
  };
}

function viewFor(data: Uint8Array): DataView {
  return new DataView(data.buffer, data.byteOffset, data.byteLength);
}
