import { describe, it, expect } from 'vitest';

import { scoreBuildReadiness, type TestResult, type QualitativeInput } from '../src/baf.js';
import type { ProjectSignals } from '../src/scan.js';

function makeSignals(overrides: Partial<ProjectSignals> = {}): ProjectSignals {
  return {
    root: '/tmp/fixture',
    fileCount: 20,
    sourceFileCount: 12,
    totalLoc: 6000,
    languages: { '.ts': 12 },
    hasReadme: true,
    hasLicense: true,
    manifest: {
      ecosystem: 'node',
      name: 'fixture',
      dependencyCount: 5,
      dependencyNames: ['react', 'express'],
      scripts: ['build', 'test'],
      hasLockfile: true,
      hasBin: false,
    },
    tests: { present: true, framework: null, testFileCount: 4, testCommand: 'npm test' },
    ci: { present: true, files: ['.github/workflows/ci.yml'] },
    committedEnvFile: false,
    secrets: { suspectCount: 0, locations: [] },
    todos: 2,
    largestSourceFiles: [{ path: 'src/index.ts', loc: 400 }],
    projectType: 'web',
    frameworks: [],
    backends: [],
    suggestedStage: 'mvp',
    threats: { verdict: 'clean', findings: [], filesScanned: 12 },
    ...overrides,
  };
}

const testsGreen: TestResult = { ran: true, total: 100, passed: 100, failed: 0 };

function dim(report: ReturnType<typeof scoreBuildReadiness>, name: string) {
  const d = report.dimensions.find((x) => x.name === name);
  if (!d) throw new Error(`dimension ${name} not found`);
  return d;
}

describe('scoreBuildReadiness — totals and bands', () => {
  it('a clean, well-equipped MVP scores only Promising WITHOUT a code-read (earn-up)', () => {
    const r = scoreBuildReadiness(makeSignals(), testsGreen, 'mvp');
    expect(r.total).toBeGreaterThanOrEqual(70);
    expect(r.total).toBeLessThan(80);
    // Security and Architecture are unverified until a real read happens.
    expect(dim(r, 'Security').grade).toBe('C');
    expect(dim(r, 'Architecture').grade).toBe('C');
  });

  it('the same project reaches Strong+ once a code-read verifies security and architecture', () => {
    const qual: QualitativeInput = { security: { rating: 90 }, architecture: { rating: 88 } };
    const r = scoreBuildReadiness(makeSignals(), testsGreen, 'mvp', qual);
    expect(r.total).toBeGreaterThanOrEqual(80);
    expect(['Strong', 'Outstanding']).toContain(r.band);
  });

  it('maps totals to the right band labels', () => {
    // Strip everything to push the score low.
    const bare = makeSignals({
      hasReadme: false,
      hasLicense: false,
      manifest: { ecosystem: 'unknown', name: null, dependencyCount: 0, dependencyNames: [], scripts: [], hasLockfile: false, hasBin: false },
      tests: { present: false, framework: null, testFileCount: 0, testCommand: null },
      ci: { present: false, files: [] },
      totalLoc: 200,
      sourceFileCount: 2,
    });
    const r = scoreBuildReadiness(bare, null, 'prototype');
    expect(r.total).toBeLessThan(70);
  });
});

describe('Security — hard criticals always bite', () => {
  it('a committed .env produces a critical risk and tanks the security score', () => {
    const r = scoreBuildReadiness(makeSignals({ committedEnvFile: true }), testsGreen, 'mvp');
    const sec = dim(r, 'Security');
    expect(sec.risks.some((x) => x.severity === 'critical')).toBe(true);
    expect(sec.score).toBeLessThanOrEqual(15);
  });

  it('hardcoded secrets produce a critical risk', () => {
    const r = scoreBuildReadiness(
      makeSignals({ secrets: { suspectCount: 2, locations: ['a.ts (openai_key)', 'b.ts (aws)'] } }),
      testsGreen,
      'mvp',
    );
    const sec = dim(r, 'Security');
    expect(sec.risks.some((x) => x.severity === 'critical')).toBe(true);
  });

  it('criticals still bite even when a glowing code-read is supplied', () => {
    const qual: QualitativeInput = { security: { rating: 100, findings: ['flawless'], risks: [] } };
    const r = scoreBuildReadiness(makeSignals({ committedEnvFile: true }), testsGreen, 'mvp', qual);
    const sec = dim(r, 'Security');
    // rating 100 -> 25, minus the .env critical (10) -> 15, never the full 25.
    expect(sec.score).toBeLessThanOrEqual(15);
    expect(sec.risks.some((x) => x.severity === 'critical')).toBe(true);
  });
});

describe('Qualitative read — upgrades grade and never lowers a clean score', () => {
  it('without a read, Security and Architecture are grade C', () => {
    const r = scoreBuildReadiness(makeSignals(), testsGreen, 'mvp');
    expect(dim(r, 'Security').grade).toBe('C');
    expect(dim(r, 'Architecture').grade).toBe('C');
  });

  it('with a read, Security and Architecture become grade A', () => {
    const qual: QualitativeInput = {
      security: { rating: 90, findings: ['layered defenses'], risks: [] },
      architecture: { rating: 88, findings: ['clean boundaries'], risks: [] },
    };
    const r = scoreBuildReadiness(makeSignals(), testsGreen, 'mvp', qual);
    expect(dim(r, 'Security').grade).toBe('A');
    expect(dim(r, 'Architecture').grade).toBe('A');
  });

  it('a thorough security read never scores below the no-read baseline', () => {
    // Signals with no hard issues but no lockfile, so the baseline took a soft hit.
    const signals = makeSignals({
      manifest: { ecosystem: 'node', name: 'x', dependencyCount: 5, dependencyNames: [], scripts: ['build', 'test'], hasLockfile: false, hasBin: false },
    });
    const baseline = dim(scoreBuildReadiness(signals, testsGreen, 'mvp'), 'Security').score;
    const withRead = dim(
      scoreBuildReadiness(signals, testsGreen, 'mvp', { security: { rating: 92 } }),
      'Security',
    ).score;
    expect(withRead).toBeGreaterThanOrEqual(baseline);
  });
});

describe('Robustness — driven by tests, stage-calibrated', () => {
  it('green tests give full robustness with grade A', () => {
    const r = scoreBuildReadiness(makeSignals(), testsGreen, 'mvp');
    const rob = dim(r, 'Robustness');
    expect(rob.score).toBe(15);
    expect(rob.grade).toBe('A');
  });

  it('failing tests produce a high-severity risk', () => {
    const r = scoreBuildReadiness(makeSignals(), { ran: true, total: 100, passed: 60, failed: 40 }, 'mvp');
    const rob = dim(r, 'Robustness');
    expect(rob.risks.some((x) => x.severity === 'high')).toBe(true);
    expect(rob.score).toBeLessThan(15);
  });

  it('no tests is penalized harder at growth stage than prototype', () => {
    const noTests = makeSignals({ tests: { present: false, framework: null, testFileCount: 0, testCommand: null } });
    const proto = dim(scoreBuildReadiness(noTests, null, 'prototype'), 'Robustness').score;
    const growth = dim(scoreBuildReadiness(noTests, null, 'growth'), 'Robustness').score;
    expect(proto).toBeGreaterThan(growth);
  });

  it('tests present but not run is partial and grade C', () => {
    const r = scoreBuildReadiness(makeSignals(), null, 'mvp');
    const rob = dim(r, 'Robustness');
    expect(rob.grade).toBe('C');
    expect(rob.score).toBeGreaterThan(0);
    expect(rob.score).toBeLessThan(15);
  });
});

describe('Top risks register', () => {
  it('sorts most severe first and caps at 8', () => {
    const r = scoreBuildReadiness(
      makeSignals({
        committedEnvFile: true,
        secrets: { suspectCount: 1, locations: ['x.ts (key)'] },
        hasReadme: false,
        ci: { present: false, files: [] },
        manifest: { ecosystem: 'node', name: 'x', dependencyCount: 5, dependencyNames: [], scripts: [], hasLockfile: false, hasBin: false },
      }),
      { ran: true, total: 10, passed: 5, failed: 5 },
      'growth',
    );
    expect(r.topRisks.length).toBeLessThanOrEqual(8);
    expect(r.topRisks[0].severity).toBe('critical');
  });
});
