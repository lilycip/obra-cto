import { describe, it, expect } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildReportJson, writeCtoReport, REPORT_DIR, REPORT_JSON } from '../src/report.js';
import type { BuildReadinessReport, TestResult } from '../src/baf.js';

function makeReport(overrides: Partial<BuildReadinessReport> = {}): BuildReadinessReport {
  return {
    stage: 'mvp',
    total: 82,
    band: 'Strong',
    verdict: 'Solid build.',
    dimensions: [
      { name: 'Security', weight: 25, score: 22, grade: 'A', findings: ['RLS enabled'], risks: [] },
      { name: 'Architecture', weight: 15, score: 13, grade: 'A', findings: [], risks: [] },
    ],
    topRisks: [{ title: 'No tests', severity: 'medium', grade: 'A', fix: 'Add tests.' }],
    ...overrides,
  };
}

const base = {
  name: 'fixture',
  root: '/tmp/fixture',
  projectType: 'web',
  frameworks: ['next'],
  backends: ['supabase'],
  stage: 'mvp' as const,
};

describe('buildReportJson', () => {
  it('produces the stable machine contract with score, dimensions, and risks', () => {
    const json = buildReportJson({
      ...base,
      report: makeReport(),
      testResult: null,
      codeReviewed: true,
    });
    expect(json.schema).toBe('obra-cto-report');
    expect(json.schemaVersion).toBe(1);
    expect(json.score.total).toBe(82);
    expect(json.score.band).toBe('Strong');
    expect(json.project.backends).toEqual(['supabase']);
    expect(json.dimensions.find((d) => d.name === 'Security')?.grade).toBe('A');
    expect(json.topRisks[0]?.title).toBe('No tests');
    expect(json.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('records test evidence when tests ran', () => {
    const testResult: TestResult = { ran: true, total: 40, passed: 40, failed: 0 };
    const json = buildReportJson({ ...base, report: makeReport(), testResult, codeReviewed: false });
    expect(json.evidence.testsRun).toBe(true);
    expect(json.evidence.testsPassed).toBe(40);
    expect(json.evidence.codeReviewed).toBe(false);
  });

  it('marks tests not run when no result is passed', () => {
    const json = buildReportJson({ ...base, report: makeReport(), testResult: null, codeReviewed: false });
    expect(json.evidence.testsRun).toBe(false);
    expect(json.evidence.testsTotal).toBeUndefined();
  });
});

describe('writeCtoReport', () => {
  it('creates the .obra directory and writes both files, readable back as JSON', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'obra-cto-report-'));
    try {
      const json = buildReportJson({ ...base, root: dir, report: makeReport(), testResult: null, codeReviewed: true });
      const written = await writeCtoReport(dir, json, '# Obra CTO Score\n82 / 100');
      expect(written.jsonPath).toBe(join(dir, REPORT_DIR, REPORT_JSON));

      const raw = await readFile(written.jsonPath, 'utf8');
      const parsed = JSON.parse(raw);
      expect(parsed.score.total).toBe(82);
      expect(parsed.tool.name).toBe('obra-cto');

      const md = await readFile(written.mdPath, 'utf8');
      expect(md).toContain('Obra CTO Score');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
