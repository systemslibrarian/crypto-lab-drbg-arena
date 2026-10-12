import { describe, it, expect } from 'vitest';
import { modeledSourceRequest } from './construction-context';
describe('90C source-request model', () => {
 it('does not claim RBG1 heals after compromise, even with the model flags set', () => {
  expect(modeledSourceRequest('RBG1', true, true)).toContain('No prediction-resistance or healing claim');
 });
 it('does not impose source-request failure on ordinary-generation policies', () => {
  expect(modeledSourceRequest('RBG2', false, false, false)).toContain('Ordinary generation policy depends');
 });
 it('propagates source failure and unavailable independent entropy', () => {
  for (const kind of ['RBG2','RBG3','RBGC'] as const) {
   expect(modeledSourceRequest(kind,true,false)).toContain('Blocked source request');
   expect(modeledSourceRequest(kind,false,true)).toContain('stolen DRBG state remains predictive');
   expect(modeledSourceRequest(kind,true,true)).toContain('proves neither full entropy nor recovery');
  }
 });
});
