import { expect, test } from '@playwright/test';

test('the source-request model distinguishes unsupported, unavailable and failed requests', async ({ page }) => {
  await page.goto('/crypto-lab-drbg-arena/');
  const result = page.locator('#construction-result');
  const kind = page.locator('#construction-class');
  await expect(result).toContainText('Simulated source request succeeds');
  await kind.selectOption('RBG1');
  await expect(result).toContainText('Unsupported after instantiation');
  await kind.selectOption('RBG2');
  await page.locator('#construction-healthy').uncheck();
  await expect(result).toContainText('Blocked source request');
  await page.locator('#construction-healthy').check();
  await page.locator('#construction-fresh').uncheck();
  await expect(result).toContainText('stolen DRBG state remains predictive');
  await page.locator('#construction-pr').uncheck();
  await expect(result).toContainText('No prediction-resistance request modeled');
  await kind.selectOption('RBG3');
  await expect(page.locator('#construction-description')).toContainText('plain DRBG expansion is not this construction');
  await expect(result).toContainText('RBG3 full-entropy generation still requires its fresh-input path');
  await kind.selectOption('RBGC');
  await expect(page.locator('#construction-description')).toContainText('children cannot seed their ancestors');
});
