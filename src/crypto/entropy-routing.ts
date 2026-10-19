/** Original teaching ledger informed by Joshua E. Hill, ICMC N20b,
 * version 20260422, slides 2–8. This models §3.1 of the 2025 final 90C;
 * it does not implement Hill's proposed RBGC or draft CMVP guidance. */
export interface RoutingSettings {
  validated: boolean;
  healthy: boolean;
  fresh: boolean;
  includeExtra: boolean;
  route: 'additional' | 'external';
}
export function entropyRouting(s: RoutingSettings): { allowed: boolean; creditedBits: number; extraBits: number; reason: string } {
  const creditedBits = s.validated && s.healthy && s.fresh ? 256 : 0;
  const extraBits = 0;
  if (s.includeExtra && s.route === 'external') return { allowed: false, creditedBits, extraBits,
    reason: 'Blocked in this 2025-final model: an unvalidated source cannot enter Get_entropy_bitstring. Route it separately as additional_input.' };
  if (creditedBits < 256) return { allowed: false, creditedBits, extraBits,
    reason: 'This modeled reseed requires 256 credited fresh bits from source A. Extra bytes from B do not satisfy that requirement.' };
  return { allowed: true, creditedBits, extraBits,
    reason: s.includeExtra ? 'Source A meets the modeled reseed budget. B is mixed as additional_input, with zero entropy credited to B.' :
      'Source A meets the modeled reseed budget. No additional input is mixed.' };
}
