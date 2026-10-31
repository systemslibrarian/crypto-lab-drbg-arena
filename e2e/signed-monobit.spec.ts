import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
test('compares signed and folded blocks with finite expected counts',async({page})=>{
  await page.goto('./');
  await page.getByRole('button',{name:'Compare original and complemented blocks'}).click();
  await expect(page.locator('#signed-result')).toContainText('1000 blocks × 16 bits');
  await expect(page.locator('#signed-result')).toContainText('finite-null');
  await page.locator('#signed-calibration').selectOption('exact');
  await expect(page.locator('#signed-result table tbody tr')).toHaveCount(10);
  const results=await new AxeBuilder({page}).include('[aria-labelledby="signed-monobit-title"]').withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
  expect(results.violations).toEqual([]);
});
