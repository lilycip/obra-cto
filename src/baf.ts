/**
 * Build Assessment Framework (BAF) — the scoring engine behind the Obra CTO Score.
 *
 * This module holds the FREE, coarse baseline rubric: it scores what a machine
 * can verify (tests that pass, a CI file that exists, secrets in the open, a
 * lockfile, docs, structure proxies). The deep, weighted BAF and the VIAF
 * investment scoring it feeds are the paid Obra CFO and are not in this file.
 *
 * Evidence grades mirror VIAF: A verified, B multiple sources, C partial or
 * inferred, D claim only, E speculation. The Obra CTO Score is built almost
 * entirely from grade A and C evidence, which is the whole point: we score what
 * is true, not what a deck says.
 */
import type { ProjectSignals, BuildStage } from './scan.js';

export type EvidenceGrade = 'A' | 'B' | 'C' | 'D' | 'E';

export type TestResult = {
  ran: boolean;
  total?: number;
  passed?: number;
  failed?: number;
  exitCode?: number;
  note?: string;
} | null;

export type DimensionResult = {
  name: string;
  weight: number;
  score: number;
  grade: EvidenceGrade;
  findings: string[];
  risks: Risk[];
};

export type Risk = {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  grade: EvidenceGrade;
  fix: string;
};

export type BuildReadinessReport = {
  stage: BuildStage;
  total: number;
  band: string;
  verdict: string;
  dimensions: DimensionResult[];
  topRisks: Risk[];
};

/** A qualitative read of one dimension, supplied by the host Claude after a code review. */
export type QualitativeDimension = {
  rating: number; // 0 to 100
  findings?: string[];
  risks?: { title: string; severity: Risk['severity']; fix: string }[];
};

export type QualitativeInput = {
  security?: QualitativeDimension;
  architecture?: QualitativeDimension;
};

function mapRisks(rs: QualitativeDimension['risks']): Risk[] {
  return (rs ?? []).map((r) => ({ title: r.title, severity: r.severity, grade: 'A' as EvidenceGrade, fix: r.fix }));
}

const SEV_RANK: Record<Risk['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Score a project's Build Readiness from mechanical signals plus optional test results. */
export function scoreBuildReadiness(
  signals: ProjectSignals,
  testResult: TestResult,
  stage: BuildStage,
  qualitative?: QualitativeInput,
  extraRisks?: Risk[],
): BuildReadinessReport {
  const dimensions: DimensionResult[] = [
    scoreSecurity(signals, stage, qualitative?.security),
    scoreProductReality(signals),
    scoreRobustness(signals, testResult, stage),
    scoreArchitecture(signals, qualitative?.architecture),
    scoreMaintainability(signals),
    scoreDeploy(signals, stage),
  ];

  const total = Math.round(dimensions.reduce((sum, d) => sum + d.score, 0));
  // Extra risks (e.g. malicious-code findings from the TL-005 tripwire) are not a
  // scored dimension; they are safety flags that ride into the risk register and
  // drive the verdict, so a repo with a backdoor reads as critical, not as a number.
  const topRisks = dimensions
    .flatMap((d) => d.risks)
    .concat(extraRisks ?? [])
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])
    .slice(0, 8);

  return {
    stage,
    total,
    band: bandFor(total),
    verdict: verdictFor(total, stage, topRisks),
    dimensions,
    topRisks,
  };
}

function clamp(n: number, max: number): number {
  return Math.max(0, Math.min(max, n));
}

// ── Security (25) ────────────────────────────────────────────────────────────
function scoreSecurity(s: ProjectSignals, stage: BuildStage, qual?: QualitativeDimension): DimensionResult {
  const findings: string[] = [];
  const risks: Risk[] = [];

  // Hard mechanical deductions. These bite regardless of any qualitative rating:
  // a committed .env stays critical even if the code reads beautifully.
  let envDeduction = 0;
  if (s.committedEnvFile) {
    envDeduction = 10;
    risks.push({
      title: 'A .env file is committed to the project',
      severity: 'critical',
      grade: 'A',
      fix: 'Remove it from the repo, rotate every value it held, and add .env to .gitignore. Commit a .env.example with empty keys instead.',
    });
  } else {
    findings.push('No committed .env file found.');
  }

  let secretDeduction = 0;
  if (s.secrets.suspectCount > 0) {
    secretDeduction = clamp(4 * s.secrets.suspectCount, 12);
    risks.push({
      title: `${s.secrets.suspectCount} possible hardcoded secret(s) in source`,
      severity: 'critical',
      grade: 'A',
      fix: `Move them to environment variables and rotate them now. First hits: ${s.secrets.locations.slice(0, 3).join('; ')}`,
    });
  } else {
    findings.push('No obvious hardcoded secrets matched the common patterns.');
  }

  let lockDeduction = 0;
  const usesDeps = s.manifest.dependencyCount > 0;
  if (usesDeps && !s.manifest.hasLockfile) {
    lockDeduction = stage === 'prototype' ? 1 : 3;
    risks.push({
      title: 'No dependency lockfile',
      severity: stage === 'growth' ? 'high' : 'medium',
      grade: 'A',
      fix: 'Commit a lockfile (package-lock.json, pnpm-lock.yaml, poetry.lock) so builds are reproducible and dependency versions are pinned.',
    });
  } else if (usesDeps) {
    findings.push('Dependencies are pinned by a lockfile.');
  }

  if (qual) {
    // A real code-read happened: the deep-security portion is set by the read.
    // Only the hard criticals (committed secrets, .env) subtract on top; soft
    // issues like a missing lockfile are already reflected in the human rating,
    // so a thorough read never scores below the hard-fact baseline. Grade A.
    const criticalDeduction = envDeduction + secretDeduction;
    const deep = Math.round((qual.rating / 100) * 25);
    const score = clamp(deep - criticalDeduction, 25);
    for (const f of qual.findings ?? []) findings.push(f);
    risks.push(...mapRisks(qual.risks));
    return { name: 'Security', weight: 25, score, grade: 'A', findings, risks };
  }

  findings.push('Security is UNVERIFIED until a code-read runs (prepare_code_review). The absence of obvious red flags is not proof the code is secure, so this dimension starts low and is earned by a real review. Run the read to verify it.');
  // Earn-up: an unexamined codebase has not demonstrated it is secure, so it sits at
  // a conservative baseline (minus any hard-fact criticals) and grade C. Only a real
  // code-read lifts it. This stops a repo from looking secure just for hiding nothing.
  const UNVERIFIED_SECURITY_BASE = 10;
  return {
    name: 'Security',
    weight: 25,
    score: clamp(UNVERIFIED_SECURITY_BASE - (envDeduction + secretDeduction + lockDeduction), 25),
    grade: 'C',
    findings,
    risks,
  };
}

// ── Product reality / what is built (20) ──────────────────────────────────────
function scoreProductReality(s: ProjectSignals): DimensionResult {
  const findings: string[] = [];
  const risks: Risk[] = [];
  let score = 0;

  if (s.manifest.ecosystem !== 'unknown') {
    score += 8;
    findings.push(`Recognised ${s.manifest.ecosystem} project${s.manifest.name ? ` (${s.manifest.name})` : ''}.`);
  } else {
    risks.push({
      title: 'No recognised project manifest',
      severity: 'medium',
      grade: 'A',
      fix: 'Add a manifest (package.json, pyproject.toml, Cargo.toml) so the project is buildable and its dependencies are declared.',
    });
  }

  if (s.totalLoc > 500) score += 6;
  if (s.sourceFileCount > 5) score += 6;

  findings.push(`${s.sourceFileCount} source files, about ${s.totalLoc} lines.`);
  findings.push('This is the ground truth the CTO captures once. The Obra CFO later holds your pitch and website claims to this captured truth.');

  return { name: 'Product reality', weight: 20, score: clamp(score, 20), grade: 'A', findings, risks };
}

// ── Robustness (15) ──────────────────────────────────────────────────────────
function scoreRobustness(s: ProjectSignals, t: TestResult, stage: BuildStage): DimensionResult {
  const findings: string[] = [];
  const risks: Risk[] = [];
  let score: number;
  let grade: EvidenceGrade;

  if (t && t.ran && (t.total ?? 0) > 0 && (t.failed ?? 0) === 0) {
    score = 15;
    grade = 'A';
    findings.push(`Test suite ran and passed (${t.passed}/${t.total}). This is grade-A evidence: the CTO ran your tests, it did not take your word.`);
  } else if (t && t.ran && (t.failed ?? 0) > 0) {
    const ratio = (t.passed ?? 0) / Math.max(1, t.total ?? 1);
    score = Math.round(4 + 8 * ratio);
    grade = 'A';
    risks.push({
      title: `${t.failed} failing test(s)`,
      severity: 'high',
      grade: 'A',
      fix: 'Get the suite green. Failing tests on the main branch erode every other signal of reliability.',
    });
    findings.push(`Test suite ran: ${t.passed}/${t.total} passed.`);
  } else if (s.tests.present) {
    score = 9;
    grade = 'C';
    findings.push(`${s.tests.testFileCount} test file(s) found but not executed this run.`);
    risks.push({
      title: 'Tests exist but were not run',
      severity: 'medium',
      grade: 'C',
      fix: `Run them (${s.tests.testCommand ?? 'your test command'}) so reliability becomes grade-A evidence instead of an assumption.`,
    });
  } else {
    score = stage === 'prototype' ? 7 : stage === 'mvp' ? 3 : 1;
    grade = 'A';
    risks.push({
      title: 'No tests found',
      severity: stage === 'growth' ? 'high' : 'medium',
      grade: 'A',
      fix: 'Add tests on the riskiest path first (money, auth, data writes). Even a handful turns reliability from a hope into a checkable fact.',
    });
  }

  if (s.todos > Math.max(20, s.totalLoc / 150)) {
    score = clamp(score - 1, 15);
    risks.push({
      title: `${s.todos} TODO/FIXME/HACK markers`,
      severity: 'low',
      grade: 'A',
      fix: 'Triage them. A high marker count signals unfinished paths a reviewer will probe.',
    });
  }

  return { name: 'Robustness', weight: 15, score: clamp(score, 15), grade, findings, risks };
}

// ── Architecture (15) ────────────────────────────────────────────────────────
function scoreArchitecture(s: ProjectSignals, qual?: QualitativeDimension): DimensionResult {
  const findings: string[] = [];
  const risks: Risk[] = [];

  let godPenalty = 0;
  const biggest = s.largestSourceFiles[0];
  if (biggest && biggest.loc > 3000) {
    godPenalty = 5;
    risks.push({
      title: `Very large file: ${biggest.path} (${biggest.loc} lines)`,
      severity: 'medium',
      grade: 'A',
      fix: 'Split god-files by responsibility. Large single files are the first thing a technical reviewer flags and the hardest to test.',
    });
  } else if (biggest && biggest.loc > 1500) {
    godPenalty = 3;
    risks.push({
      title: `Large file: ${biggest.path} (${biggest.loc} lines)`,
      severity: 'low',
      grade: 'A',
      fix: 'Consider splitting it as the project grows.',
    });
  } else {
    findings.push('No oversized god-files detected.');
  }

  const langCount = Object.keys(s.languages).length;
  if (langCount > 0) findings.push(`Primary languages: ${Object.keys(s.languages).join(', ')}.`);

  if (qual) {
    const base = Math.round((qual.rating / 100) * 15);
    const score = clamp(base - godPenalty, 15);
    for (const f of qual.findings ?? []) findings.push(f);
    risks.push(...mapRisks(qual.risks));
    return { name: 'Architecture', weight: 15, score, grade: 'A', findings, risks };
  }

  findings.push('Architecture is UNVERIFIED until a code-read runs. This is a size-based proxy only, not an assessment of structure, so it starts low and is earned by a real review. Run the read to verify it.');
  // Earn-up: same posture as Security. Unexamined structure sits at a conservative
  // baseline (minus any god-file penalty) and grade C until a code-read lifts it.
  const UNVERIFIED_ARCH_BASE = 6;
  return { name: 'Architecture', weight: 15, score: clamp(UNVERIFIED_ARCH_BASE - godPenalty, 15), grade: 'C', findings, risks };
}

// ── Maintainability (15) ──────────────────────────────────────────────────────
function scoreMaintainability(s: ProjectSignals): DimensionResult {
  const findings: string[] = [];
  const risks: Risk[] = [];
  let score = 6;

  if (s.hasReadme) {
    score += 4;
    findings.push('README present.');
  } else {
    risks.push({
      title: 'No README',
      severity: 'medium',
      grade: 'A',
      fix: 'Add a README that states what the project does, how to run it, and how to test it. It is the first thing any reviewer or collaborator opens.',
    });
  }

  if (s.hasLicense) {
    score += 2;
    findings.push('LICENSE present.');
  }

  if (s.tests.present) {
    score += 3;
    findings.push('Tests aid future changes.');
  }

  if (s.todos > Math.max(20, s.totalLoc / 150)) {
    score -= 2;
  }

  return { name: 'Maintainability', weight: 15, score: clamp(score, 15), grade: 'A', findings, risks };
}

// ── Deploy readiness (10) ─────────────────────────────────────────────────────
function scoreDeploy(s: ProjectSignals, stage: BuildStage): DimensionResult {
  const findings: string[] = [];
  const risks: Risk[] = [];
  let score = 0;
  let grade: EvidenceGrade = 'C';

  if (s.ci.present) {
    score += 5;
    grade = 'A';
    findings.push(`CI configured: ${s.ci.files.join(', ')}.`);
  } else {
    risks.push({
      title: 'No CI pipeline detected',
      severity: stage === 'growth' ? 'high' : 'medium',
      grade: 'C',
      fix: 'Add a CI workflow that runs build and tests on every push. This is the one deploy signal code alone cannot confirm, so its absence counts against readiness.',
    });
  }

  if (s.manifest.hasLockfile) score += 2;
  if (s.manifest.ecosystem === 'node' && s.manifest.scripts.includes('build')) {
    score += 2;
    findings.push('Build script present.');
  }
  if (s.hasReadme) score += 1;

  return { name: 'Deploy readiness', weight: 10, score: clamp(score, 10), grade, findings, risks };
}

function bandFor(total: number): string {
  if (total >= 90) return 'Outstanding';
  if (total >= 80) return 'Strong';
  if (total >= 70) return 'Promising';
  if (total >= 60) return 'Significant gaps';
  if (total >= 50) return 'Early';
  return 'Not yet ready';
}

function verdictFor(total: number, stage: BuildStage, risks: Risk[]): string {
  const criticals = risks.filter((r) => r.severity === 'critical').length;
  const stageLabel = stage === 'prototype' ? 'a prototype' : stage === 'mvp' ? 'an MVP' : 'a growth-stage product';
  const head = `Scored as ${stageLabel}: ${total}/100 (${bandFor(total)}).`;
  if (criticals > 0) {
    return `${head} ${criticals} critical issue(s) would stop a technical reviewer cold. Close those first; they are cheap to fix and expensive to be caught on.`;
  }
  if (total >= 80) {
    return `${head} This holds up to a technical diligence read. The next lift is the investor-facing translation, which is the Obra CFO's job.`;
  }
  return `${head} Solid base with clear, fixable gaps. The Top Risks below are ordered by what a reviewer would flag first.`;
}
