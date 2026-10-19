import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('routing refuses false credit and demonstrates additional-input influence', async ({page}) => {
  await page.goto('./');
  await page.locator('#routing-run').click();
  await expect(page.locator('#routing-output')).toContainText('B changed the output');
  const rows = await page.locator('#routing-output code').allTextContents();
  expect(new Set(rows).size).toBe(3);
  await page.locator('#routing-fresh').uncheck();
  await expect(page.locator('#routing-run')).toBeDisabled();
  await expect(page.locator('#routing-ledger')).toContainText('A = 0 bits; B = 0 bits');
  await expect(page.locator('#routing-output')).toBeEmpty();
  await page.locator('#routing-fresh').check();
  await page.locator('#routing-route').selectOption('external');
  await expect(page.locator('#routing-run')).toBeDisabled();
  await page.locator('#routing-extra').uncheck();
  await page.locator('#routing-run').click();
  await expect(page.locator('#routing-output')).toContainText('Outputs match');
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect((await new AxeBuilder({page}).include('#entropy-routing').analyze()).violations).toEqual([]);
});
