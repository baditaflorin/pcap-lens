import { analyzeCapture } from '@/features/analyzer/analyze';
import { createSampleCapture } from '@/features/sample/sampleCapture';

describe('analyzeCapture', () => {
  it('decodes protocols, flows, and default IDS matches', () => {
    const result = analyzeCapture(createSampleCapture(), 'sample.pcap');

    expect(result.schemaVersion).toBe('analysis.v1');
    expect(result.summary.packetCount).toBe(5);
    expect(result.summary.flowCount).toBeGreaterThanOrEqual(3);
    expect(result.protocolCounts.map((count) => count.protocol)).toEqual(
      expect.arrayContaining(['HTTP', 'DNS', 'TLS'])
    );
    expect(result.rules.matches.map((match) => match.sid)).toEqual(
      expect.arrayContaining(['1000001', '1000002', '1000004', '1000005'])
    );
  });
});
