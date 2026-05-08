import { chromium } from 'playwright';

const url = process.env.SCREENSHOT_URL ?? 'http://127.0.0.1:4173/pcap-lens/';
const output = process.env.SCREENSHOT_OUTPUT ?? 'docs/screenshot.png';

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 1440, height: 1000 },
  deviceScaleFactor: 1
});

await page.goto(url, { waitUntil: 'networkidle' });
await page.getByRole('button', { name: 'Run sample' }).click();
await page.getByRole('heading', { name: 'Flow Graph' }).waitFor();
await page.screenshot({ path: output, fullPage: true });

await browser.close();
