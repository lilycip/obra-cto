/**
 * Report handoff — the CTO writes its verdict to a shared `.obra/` directory so a
 * second tool (the Obra CFO) can read it without re-parsing prose.
 *
 * `.obra/cto-report.json` is the machine contract: stable, versioned fields the CFO
 * reads directly (score, band, stage, per-dimension grades, top risks, whether tests
 * ran and whether the code was reviewed). `.obra/cto-report.md` rides along as the
 * human-readable copy.
 *
 * The directory lives inside the project being scored, not in a global location, and
 * the CTO creates it when it writes. Nothing needs to exist in advance. This process
 * still makes no network calls; a report file is a local artifact, like a build output.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { BuildReadinessReport, TestResult, EvidenceGrade } from './baf.js';
import type { BuildStage } from './scan.js';

/** Kept in sync with package.json. The CFO reads this to know which contract it got. */
export const TOOL_VERSION = '0.3.0';

export const REPORT_DIR = '.obra';
export const REPORT_JSON = 'cto-report.json';
export const REPORT_MD = 'cto-report.md';

/**
 * The machine contract the Obra CFO consumes. Additive changes keep `schemaVersion`;
 * a breaking field change bumps it. The CFO should tolerate unknown extra fields.
 */
export type CtoReportJson = {
  schema: 'obra-cto-report';
  schemaVersion: 1;
  tool: { name: 'obra-cto'; version: string };
  generatedAt: string;
  project: {
    name: string | null;
    root: string;
    projectType: string;
    frameworks: string[];
    backends: string[];
    stage: BuildStage;
  };
  score: { total: number; band: string; verdict: string };
  dimensions: Array<{ name: string; score: number; weight: number; grade: EvidenceGrade; findings: string[] }>;
  topRisks: Array<{ title: string; severity: string; grade: EvidenceGrade; fix: string }>;
  evidence: {
    testsRun: boolean;
    testsTotal?: number;
    testsPassed?: number;
    testsFailed?: number;
    codeReviewed: boolean;
  };
};

export type BuildReportArgs = {
  name: string | null;
  root: string;
  projectType: string;
  frameworks: string[];
  backends: string[];
  stage: BuildStage;
  report: BuildReadinessReport;
  testResult: TestResult;
  codeReviewed: boolean;
};

/** Assemble the JSON contract from a scored report plus its scan context. */
export function buildReportJson(args: BuildReportArgs): CtoReportJson {
  const { report, testResult } = args;
  const evidence: CtoReportJson['evidence'] = {
    testsRun: testResult !== null && testResult.ran === true,
    codeReviewed: args.codeReviewed,
    ...(testResult && testResult.total !== undefined ? { testsTotal: testResult.total } : {}),
    ...(testResult && testResult.passed !== undefined ? { testsPassed: testResult.passed } : {}),
    ...(testResult && testResult.failed !== undefined ? { testsFailed: testResult.failed } : {}),
  };
  return {
    schema: 'obra-cto-report',
    schemaVersion: 1,
    tool: { name: 'obra-cto', version: TOOL_VERSION },
    generatedAt: new Date().toISOString(),
    project: {
      name: args.name,
      root: args.root,
      projectType: args.projectType,
      frameworks: args.frameworks,
      backends: args.backends,
      stage: args.stage,
    },
    score: { total: report.total, band: report.band, verdict: report.verdict },
    dimensions: report.dimensions.map((d) => ({
      name: d.name,
      score: d.score,
      weight: d.weight,
      grade: d.grade,
      findings: d.findings,
    })),
    topRisks: report.topRisks.map((r) => ({
      title: r.title,
      severity: r.severity,
      grade: r.grade,
      fix: r.fix,
    })),
    evidence,
  };
}

export type WrittenReport = { dir: string; jsonPath: string; mdPath: string };

/**
 * Write the JSON contract and the markdown copy into `<root>/.obra/`, creating the
 * directory if it does not exist. Returns the paths written.
 */
export async function writeCtoReport(
  root: string,
  json: CtoReportJson,
  markdown: string,
): Promise<WrittenReport> {
  const dir = join(root, REPORT_DIR);
  await mkdir(dir, { recursive: true });
  const jsonPath = join(dir, REPORT_JSON);
  const mdPath = join(dir, REPORT_MD);
  await writeFile(jsonPath, JSON.stringify(json, null, 2) + '\n', 'utf8');
  await writeFile(mdPath, markdown.endsWith('\n') ? markdown : markdown + '\n', 'utf8');
  return { dir, jsonPath, mdPath };
}
