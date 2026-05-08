import { analyzeCapture } from '@/features/analyzer/analyze';
import { createSampleCapture } from '@/features/sample/sampleCapture';
import { parseRules } from './suricata';

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
