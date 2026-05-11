import type { InternalDecodedPacket } from '@/features/analyzer/types';
import { analyzeCapture } from '@/features/analyzer/analyze';
import { createSampleCapture } from '@/features/sample/sampleCapture';
import { matchRules, parseFlowOption, parseRules } from './suricata';

describe('Suricata-style rule subset', () => {
  it('parses content rules with nocase modifiers', () => {
    const { rules, errors } = parseRules(
      'alert http any any -> any any (msg:"case"; content:"get"; nocase; sid:42; rev:1;)'
    );

    expect(errors).toEqual([]);
    expect(rules).toHaveLength(1);
    expect(rules[0]?.contents[0]?.nocase).toBe(true);
  });

  it('matches the synthetic HTTP packet', () => {
    const result = analyzeCapture(
      createSampleCapture(),
      'sample.pcap',
      'alert http any any -> any any (msg:"GET request"; content:"GET"; sid:99; rev:1;)'
    );

    expect(result.rules.matches).toHaveLength(1);
    expect(result.rules.matches[0]?.sid).toBe('99');
  });
});

describe('flow-aware rule matching', () => {
  function makeTcpPacket(
    index: number,
    src: string,
    srcPort: number,
    dst: string,
    dstPort: number,
    flags: string[],
    summary = ''
  ): InternalDecodedPacket {
    return {
      index,
      timestampMicros: index * 1000,
      timestampIso: new Date(index * 1000).toISOString(),
      capturedLength: 60,
      originalLength: 60,
      linkType: 1,
      protocol: 'TCP',
      source: src,
      sourcePort: srcPort,
      destination: dst,
      destinationPort: dstPort,
      summary,
      layers: ['ethernet', 'ip', 'tcp'],
      payloadPreview: '',
      warnings: [],
      tcp: { flags, sequence: 0, acknowledgment: 0 },
      matchedRuleIds: [],
      networkProtocol: 'IPv4',
      transportProtocol: 'TCP',
      payload: new Uint8Array(),
      applicationText: ''
    };
  }

  it('parseFlowOption parses each supported keyword', () => {
    expect(parseFlowOption('established')).toEqual({ established: true });
    expect(parseFlowOption('established,to_server')).toEqual({
      established: true,
      toServer: true
    });
    expect(parseFlowOption('to_client')).toEqual({ toClient: true });
    // Unknown keywords are ignored — Suricata supports more than we
    // do, but we want forward compatibility instead of rule-parse errors.
    expect(parseFlowOption('established,bogus_keyword')).toEqual({ established: true });
  });

  it('flow:established suppresses the rule on the first SYN', () => {
    const { rules } = parseRules(
      'alert tcp any any -> any any (msg:"after handshake"; flow:established; sid:1; rev:1;)'
    );
    const syn = makeTcpPacket(0, '10.0.0.1', 1234, '10.0.0.2', 80, ['SYN']);
    const matches = matchRules([syn], rules);
    expect(matches).toHaveLength(0);
  });

  it('flow:established fires once the SYN/ACK has been seen', () => {
    const { rules } = parseRules(
      'alert tcp any any -> any any (msg:"after handshake"; flow:established; sid:1; rev:1;)'
    );
    const syn = makeTcpPacket(0, '10.0.0.1', 1234, '10.0.0.2', 80, ['SYN']);
    const synAck = makeTcpPacket(1, '10.0.0.2', 80, '10.0.0.1', 1234, ['SYN', 'ACK']);
    const data = makeTcpPacket(2, '10.0.0.1', 1234, '10.0.0.2', 80, ['ACK', 'PSH']);
    const matches = matchRules([syn, synAck, data], rules);
    // The SYN/ACK and the post-handshake data packet both satisfy
    // flow:established. The initial SYN must not match.
    expect(matches.map((m) => m.packetIndex).sort()).toEqual([1, 2]);
  });

  it('flow:to_server requires the original-SYN direction', () => {
    const { rules } = parseRules(
      'alert tcp any any -> any any (msg:"client to server"; flow:established,to_server; sid:1; rev:1;)'
    );
    const syn = makeTcpPacket(0, '10.0.0.1', 1234, '10.0.0.2', 80, ['SYN']);
    const synAck = makeTcpPacket(1, '10.0.0.2', 80, '10.0.0.1', 1234, ['SYN', 'ACK']);
    const clientData = makeTcpPacket(2, '10.0.0.1', 1234, '10.0.0.2', 80, ['ACK', 'PSH']);
    const serverData = makeTcpPacket(3, '10.0.0.2', 80, '10.0.0.1', 1234, ['ACK', 'PSH']);
    const matches = matchRules([syn, synAck, clientData, serverData], rules);
    // Only the client→server packet should match. The SYN/ACK is
    // server→client and the initial SYN can't be established.
    expect(matches.map((m) => m.packetIndex)).toEqual([2]);
  });

  it('legacy stateless rules still match the first packet on a flow', () => {
    const { rules } = parseRules(
      'alert tcp any any -> any 80 (msg:"any HTTP"; sid:42; rev:1;)'
    );
    const syn = makeTcpPacket(0, '10.0.0.1', 1234, '10.0.0.2', 80, ['SYN']);
    const matches = matchRules([syn], rules);
    expect(matches).toHaveLength(1);
  });
});
