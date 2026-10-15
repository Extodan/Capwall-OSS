import { describe, expect, it } from 'vitest'
import {
  factorsForCapabilities,
  RISK_FACTORS,
  riskLevel,
  riskScore,
} from '../src/index.js'

describe('risk scoring', () => {
  it('empty factors score 0 / low', () => {
    expect(riskScore([])).toBe(0)
    expect(riskLevel(0)).toBe('low')
  })

  it('sums weights and clamps to 100', () => {
    expect(riskScore([{ id: 'obfuscation' }, { id: 'child_process' }])).toBe(75)
    const everything = Object.keys(RISK_FACTORS).map((id) => ({ id: id as never }))
    expect(riskScore(everything)).toBe(100)
  })

  it('level buckets', () => {
    expect(riskLevel(19)).toBe('low')
    expect(riskLevel(20)).toBe('medium')
    expect(riskLevel(45)).toBe('high')
    expect(riskLevel(70)).toBe('critical')
  })

  it('maps capabilities to factors', () => {
    const factors = factorsForCapabilities(['env.read', 'http.request', 'child_process'])
    expect(factors.map((f) => f.id).sort()).toEqual(['child_process', 'env-access', 'network-capability'])
  })
})
