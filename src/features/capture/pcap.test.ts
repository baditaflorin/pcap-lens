import { parseCapture } from '@/features/capture/pcap';
import { createSampleCapture } from '@/features/sample/sampleCapture';

describe('parseCapture', () => {
  it('parses the synthetic classic pcap fixture', () => {
    const capture = parseCapture(createSampleCapture());

    expect(capture.format).toBe('pcap');
    expect(capture.linkType).toBe(1);
    expect(capture.packets).toHaveLength(5);
    expect(capture.warnings).toEqual([]);
  });
});
