import { expect, test } from '@playwright/test';

test('loads the sample capture and shows IDS matches', async ({ page }) => {
  await page.goto('/pcap-lens/');
  await expect(page.getByRole('heading', { name: 'pcap-lens' })).toBeVisible();

  await page.getByRole('button', { name: 'Run sample' }).click();

  await expect(page.getByRole('heading', { name: 'Flow Graph' })).toBeVisible();
  const findings = page.locator('.panel').filter({ has: page.getByRole('heading', { name: 'IDS Matches' }) });
  await expect(findings.getByText('HTTP request observed', { exact: true })).toBeVisible();
  await expect(page.getByText('Version')).toBeVisible();
  await expect(page.getByRole('link', { name: /Star on GitHub/i })).toHaveAttribute(
    'href',
    'https://github.com/baditaflorin/pcap-lens'
  );
});
