#!/usr/bin/env node
/**
 * Obra CTO — a local-first MCP server.
 *
 * Install it in your own Claude. Your Claude reads your codebase on your machine
 * and runs your tests there. This server returns mechanical signals and a Build
 * Readiness verdict. Your source never leaves your machine, and this process
 * makes no network calls. That is the deal: a code tool that exfiltrates code
 * would be a contradiction.
 *
 * Tools:
 *   - scan_project        gather mechanical signals (counts, tests, CI, secrets)
 *   - run_tests           run the project's test suite (executes code; your host
 *                         asks before running) and parse pass/fail counts
 *   - score_build_readiness  produce the Obra CTO Score with evidence grades
 *
 * The deep weighted scoring, the investor-facing materials, and the market
 * intelligence are the paid Obra CFO. This is the free preview of the lineup.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { spawn } from 'node:child_process';

import { scanProject, type BuildStage } from './scan.js';
import { scoreBuildReadiness, type TestResult, type QualitativeInput } from './baf.js';
import { prepareCodeReview } from './review.js';
import { checkDependencies } from './deps.js';

const server = new McpServer({ name: 'obra-cto', version: '0.0.1' });

const STAGES = ['prototype', 'mvp', 'growth'] as const;

const QUAL_DIM_SCHEMA = z.object({
  rating: z.number().describe('0 to 100, graded honestly against the project stage.'),
  findings: z.array(z.string()).optional(),
  risks: z
    .array(
      z.object({
        title: z.string(),
        severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
        fix: z.string(),
      }),
    )
    .optional(),
});

const QUALITATIVE_SCHEMA = z.object({
  security: QUAL_DIM_SCHEMA.optional(),
  architecture: QUAL_DIM_SCHEMA.optional(),
});

server.registerTool(
  'scan_project',
  {
    title: 'Scan project',
    description:
      'Read a local project and return mechanical Build Readiness signals: file and line counts, languages, test files, CI config, lockfile, docs, and a redacted scan for hardcoded secrets. Returns signals only, never your source. Run this first.',
    inputSchema: {
      path: z
        .string()
        .optional()
        .describe('Absolute path to the project root. Defaults to the current working directory.'),
    },
  },
  async ({ path }) => {
    const root = path ?? process.cwd();
    const signals = await scanProject(root);
    return {
      content: [
        { type: 'text', text: formatSignals(signals) },
        { type: 'text', text: '```json\n' + JSON.stringify(signals, null, 2) + '\n```' },
      ],
    };
  },
);

server.registerTool(
  'run_tests',
  {
    title: 'Run tests',
    description:
      "Run the project's test suite on this machine and parse pass/fail counts. This EXECUTES code, so your host will ask before it runs. A green suite is the strongest grade-A reliability evidence the Obra CTO Score can use. Pass the result numbers to score_build_readiness.",
    inputSchema: {
      path: z.string().optional().describe('Project root. Defaults to the current working directory.'),
      command: z
        .string()
        .optional()
        .describe('Override the test command (e.g. "pytest -q"). Defaults to the detected command.'),
    },
    annotations: { title: 'Run tests', readOnlyHint: false, openWorldHint: false },
  },
  async ({ path, command }) => {
    const root = path ?? process.cwd();
    const signals = await scanProject(root);
    const cmd = command ?? signals.tests.testCommand;
    if (!cmd) {
      return {
        content: [
          {
            type: 'text',
            text: 'No test command detected. Pass `command` explicitly, or add a test script to your manifest.',
          },
        ],
      };
    }
    const result = await runCommand(cmd, root);
    const parsed = parseTestOutput(result.output);
    const payload: TestResult = {
      ran: true,
      exitCode: result.code,
      ...(parsed.total !== undefined ? { total: parsed.total } : {}),
      ...(parsed.passed !== undefined ? { passed: parsed.passed } : {}),
      ...(parsed.failed !== undefined ? { failed: parsed.failed } : {}),
      note: `command: ${cmd}; exit ${result.code}`,
    };
    return {
      content: [
        {
          type: 'text',
          text:
            `Ran: ${cmd}\nExit code: ${result.code}\n` +
            (parsed.total !== undefined
              ? `Parsed: ${parsed.passed ?? '?'} passed, ${parsed.failed ?? 0} failed of ${parsed.total}.`
              : 'Could not parse counts from output; see exit code.'),
        },
        { type: 'text', text: '```json\n' + JSON.stringify(payload, null, 2) + '\n```' },
      ],
    };
  },
);

server.registerTool(
  'check_dependencies',
  {
    title: 'Check dependencies for known CVEs',
    description:
      "Query OSV.dev for known vulnerabilities in the project's locked dependencies, using exact versions from package-lock.json. Only package names and versions are sent, never your code. Real, current CVE data. Feed any findings into your security assessment.",
    inputSchema: {
      path: z.string().optional().describe('Project root. Defaults to the current working directory.'),
    },
    annotations: { title: 'Check dependencies', readOnlyHint: true, openWorldHint: true },
  },
  async ({ path }) => {
    const root = path ?? process.cwd();
    const result = await checkDependencies(root);
    if (!result.ok) {
      return { content: [{ type: 'text', text: `Dependency check could not run: ${result.reason}` }] };
    }
    if (result.vulnerable.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `Checked ${result.checked} ${result.ecosystem} dependencies against OSV. No known vulnerabilities found.`,
          },
        ],
      };
    }
    const lines = result.vulnerable.map((v) => `- ${v.name}@${v.version}: ${v.vulnIds.join(', ')}`);
    return {
      content: [
        {
          type: 'text',
          text:
            `Checked ${result.checked} ${result.ecosystem} dependencies against OSV.\n` +
            `${result.vulnerable.length} package(s) with known vulnerabilities:\n${lines.join('\n')}\n\n` +
            `Look up any ID at https://osv.dev/. Treat these as Security findings.`,
        },
      ],
    };
  },
);

server.registerTool(
  'prepare_code_review',
  {
    title: 'Prepare code review',
    description:
      'Select the highest-signal files (security-relevant paths, entry points, large files) and return their contents on this machine, with a review checklist. YOU, the host model, then read them and produce a structured security and architecture assessment, which you pass to score_build_readiness as `qualitative`. This is what upgrades those dimensions from inferred (grade C) to verified (grade A). Files stay local.',
    inputSchema: {
      path: z.string().optional().describe('Project root. Defaults to the current working directory.'),
      max_files: z.number().optional().describe('Maximum files to return (default 12).'),
    },
  },
  async ({ path, max_files }) => {
    const root = path ?? process.cwd();
    const signals = await scanProject(root);
    const bundle = await prepareCodeReview(root, {
      projectType: signals.projectType,
      backends: signals.backends,
      maxFiles: max_files ?? 12,
    });
    const checklistMd = bundle.checklist.sections
      .map((s) => `## ${s.title}\n${s.items.map((i) => `- ${i}`).join('\n')}`)
      .join('\n\n');
    const header =
      `# Code review bundle: ${bundle.root}\n` +
      `Assessed as: ${bundle.projectType}${signals.frameworks.length ? ` (${signals.frameworks.join(', ')})` : ''}` +
      `${signals.backends.length ? ` | backend: ${signals.backends.join(', ')}` : ''}\n` +
      `${bundle.files.length} file(s) selected${bundle.truncated ? ' (truncated to budget)' : ''}.\n\n` +
      `## System map (the shape, for the design red-team)\n\`\`\`\n${bundle.systemMap}\n\`\`\`\n\n` +
      `${checklistMd}\n\n` +
      `## What to do next\n${bundle.instructions}`;
    const fileBlocks = bundle.files.map(
      (f) => `### ${f.path}  _(${f.reason})_\n\n\`\`\`\n${f.content}\n\`\`\``,
    );
    return { content: [{ type: 'text', text: [header, ...fileBlocks].join('\n\n') }] };
  },
);

server.registerTool(
  'score_build_readiness',
  {
    title: 'Score Build Readiness',
    description:
      'Produce the Obra CTO Score (0 to 100) with a per-dimension breakdown, evidence grades, and a Top Risks register. Scan runs automatically. If you ran run_tests first, pass its numbers so reliability becomes grade-A evidence.',
    inputSchema: {
      path: z.string().optional().describe('Project root. Defaults to the current working directory.'),
      stage: z
        .enum(STAGES)
        .optional()
        .describe('Calibrate expectations to your stage: prototype, mvp, or growth. Defaults to a detected guess.'),
      tests_total: z.number().optional().describe('Total tests, from a prior run_tests call.'),
      tests_passed: z.number().optional().describe('Passing tests, from a prior run_tests call.'),
      tests_failed: z.number().optional().describe('Failing tests, from a prior run_tests call.'),
      qualitative: QUALITATIVE_SCHEMA.optional().describe(
        'Your structured security and architecture assessment from prepare_code_review. Supplying it upgrades those dimensions to grade A.',
      ),
    },
  },
  async ({ path, stage, tests_total, tests_passed, tests_failed, qualitative }) => {
    const root = path ?? process.cwd();
    const signals = await scanProject(root);
    const chosenStage: BuildStage = stage ?? signals.suggestedStage;
    const testResult: TestResult =
      tests_total !== undefined
        ? {
            ran: true,
            total: tests_total,
            ...(tests_passed !== undefined ? { passed: tests_passed } : {}),
            ...(tests_failed !== undefined ? { failed: tests_failed } : {}),
          }
        : null;
    const report = scoreBuildReadiness(signals, testResult, chosenStage, qualitative as QualitativeInput | undefined);
    return { content: [{ type: 'text', text: formatReport(report, signals.manifest.name, signals.projectType, signals.frameworks) }] };
  },
);

// ── Formatting ────────────────────────────────────────────────────────────────

function formatSignals(s: Awaited<ReturnType<typeof scanProject>>): string {
  const lines: string[] = [];
  lines.push(`# Scan: ${s.manifest.name ?? s.root}`);
  lines.push(`- Ecosystem: ${s.manifest.ecosystem}; dependencies: ${s.manifest.dependencyCount}; lockfile: ${s.manifest.hasLockfile ? 'yes' : 'no'}`);
  lines.push(`- Project type: ${s.projectType}${s.frameworks.length ? ` (${s.frameworks.join(', ')})` : ''}`);
  if (s.backends.length) lines.push(`- Backend-as-a-Service: ${s.backends.join(', ')} (data is protected by access rules, not client code)`);
  lines.push(`- Source: ${s.sourceFileCount} files, ~${s.totalLoc} lines; languages: ${Object.keys(s.languages).join(', ') || 'none detected'}`);
  lines.push(`- Tests: ${s.tests.present ? `${s.tests.testFileCount} file(s)` : 'none'}${s.tests.testCommand ? `; command: ${s.tests.testCommand}` : ''}`);
  lines.push(`- CI: ${s.ci.present ? s.ci.files.join(', ') : 'none detected'}`);
  lines.push(`- Docs: README ${s.hasReadme ? 'yes' : 'no'}, LICENSE ${s.hasLicense ? 'yes' : 'no'}`);
  lines.push(`- Hygiene: committed .env ${s.committedEnvFile ? 'YES (risk)' : 'no'}; secret hits ${s.secrets.suspectCount}; TODO markers ${s.todos}`);
  lines.push(`- Suggested stage: ${s.suggestedStage}`);
  lines.push('');
  lines.push('Next: optionally call run_tests, then call score_build_readiness.');
  return lines.join('\n');
}

function formatReport(
  r: ReturnType<typeof scoreBuildReadiness>,
  name: string | null,
  projectType?: string,
  frameworks?: string[],
): string {
  const lines: string[] = [];
  lines.push(`# Obra CTO Score${name ? `: ${name}` : ''}`);
  lines.push('');
  lines.push(`## ${r.total} / 100 — ${r.band}`);
  lines.push('');
  if (projectType) {
    lines.push(`Assessed as: **${projectType}**${frameworks && frameworks.length ? ` (${frameworks.join(', ')})` : ''}`);
    lines.push('');
  }
  lines.push(r.verdict);
  lines.push('');
  lines.push('| Dimension | Score | Evidence |');
  lines.push('|---|---|---|');
  for (const d of r.dimensions) {
    lines.push(`| ${d.name} | ${d.score} / ${d.weight} | ${d.grade} |`);
  }
  lines.push(`| **Total** | **${r.total} / 100** | |`);
  lines.push('');
  if (r.topRisks.length > 0) {
    lines.push('## Top Risks');
    lines.push('');
    for (const risk of r.topRisks) {
      lines.push(`- **[${risk.severity}]** ${risk.title} _(evidence ${risk.grade})_`);
      lines.push(`  - Fix: ${risk.fix}`);
    }
    lines.push('');
  }
  lines.push('## Notes by dimension');
  for (const d of r.dimensions) {
    if (d.findings.length === 0) continue;
    lines.push(`- **${d.name}**: ${d.findings.join(' ')}`);
  }
  lines.push('');
  lines.push('---');
  lines.push('Evidence grades: A verified, B multiple sources, C partial or inferred, D claim only, E speculation. The Obra CTO Score is built from grade A and C evidence: what is true in your code, not what a deck says.');
  lines.push('');
  lines.push('Next role: the Obra CFO turns this verified picture into funding-ready materials and the EU loan, grant, and investor path. Join the preview at get-obra.com.');
  return lines.join('\n');
}

// ── Test running ──────────────────────────────────────────────────────────────

function runCommand(cmd: string, cwd: string): Promise<{ code: number; output: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, { cwd, shell: true });
    let output = '';
    const cap = (buf: Buffer) => {
      output += buf.toString();
      if (output.length > 200_000) output = output.slice(-200_000);
    };
    child.stdout.on('data', cap);
    child.stderr.on('data', cap);
    child.on('error', (err) => resolve({ code: -1, output: output + `\n[spawn error] ${err.message}` }));
    child.on('close', (code) => resolve({ code: code ?? -1, output }));
  });
}

function parseTestOutput(out: string): { total?: number; passed?: number; failed?: number } {
  // vitest / jest: "Tests  3 failed | 36 passed (39)" or "X passed".
  const vitest = /Tests\s+(?:(\d+)\s+failed\s+\|\s+)?(\d+)\s+passed(?:\s+\((\d+)\))?/i.exec(out);
  if (vitest) {
    const failed = vitest[1] ? Number(vitest[1]) : 0;
    const passed = Number(vitest[2]);
    const total = vitest[3] ? Number(vitest[3]) : passed + failed;
    return { total, passed, failed };
  }
  // jest summary: "Tests: 1 failed, 12 passed, 13 total"
  const jest = /Tests:\s+(?:(\d+)\s+failed,\s+)?(\d+)\s+passed,\s+(\d+)\s+total/i.exec(out);
  if (jest) {
    const failed = jest[1] ? Number(jest[1]) : 0;
    return { failed, passed: Number(jest[2]), total: Number(jest[3]) };
  }
  // pytest: "==== 3 failed, 12 passed in 1.2s ====" or "12 passed"
  const pyFail = /(\d+)\s+failed,\s+(\d+)\s+passed/i.exec(out);
  if (pyFail) {
    const failed = Number(pyFail[1]);
    const passed = Number(pyFail[2]);
    return { failed, passed, total: passed + failed };
  }
  const pyPass = /(\d+)\s+passed/i.exec(out);
  if (pyPass) {
    const passed = Number(pyPass[1]);
    return { failed: 0, passed, total: passed };
  }
  return {};
}

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // eslint-disable-next-line no-console
  console.error('obra-cto MCP server running on stdio');
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('obra-cto failed to start:', err);
  process.exit(1);
});
