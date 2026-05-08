import { DEFAULT_RULES } from '@/features/rules/suricata';
import { z } from 'zod';

const rulesSchema = z.string().max(200_000).catch(DEFAULT_RULES);
const rulesKey = 'pcap-lens.rules.v1';

export function loadRules(): string {
  if (typeof localStorage === 'undefined') {
    return DEFAULT_RULES;
  }

  return rulesSchema.parse(localStorage.getItem(rulesKey) ?? DEFAULT_RULES);
}

export function saveRules(rules: string): void {
  localStorage.setItem(rulesKey, rules);
}

export function clearRules(): void {
  localStorage.removeItem(rulesKey);
}
