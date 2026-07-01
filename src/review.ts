/**
 * Code-read preparation — the depth behind the Obra CTO Score.
 *
 * The mechanical scan grades hard facts. The deep dimensions (security reasoning,
 * architecture quality) need a real read of the code. This module picks the
 * highest-signal files and hands their contents to the host Claude ON THIS
 * MACHINE, alongside a checklist of review questions. The host reads them and
 * returns a structured assessment, which the scorer folds in to upgrade those
 * dimensions from inferred (grade C) to verified (grade A).
 *
 * Nothing here sends data anywhere. The file contents go to your own Claude,
 * which is already reading your machine. The checklist holds the QUESTIONS, never
 * the scoring weights, which stay in baf.ts.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { ProjectType } from './scan.js';

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt',
  'coverage', 'vendor', '__pycache__', '.venv', 'venv', '.turbo', '.cache',
]);

const SOURCE_EXTS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.rs', '.java', '.rb', '.php', '.cs',
  '.vue', '.svelte', '.c', '.cpp', '.swift', '.kt',
]);

/** Path or name fragments that mark security-relevant code. */
const SECURITY_HINTS = [
  'auth', 'login', 'signin', 'signup', 'password', 'passwd', 'token', 'jwt',
  'session', 'crypto', 'hash', 'secret', 'oauth', 'permission', 'role', 'acl',
  'admin', 'middleware', 'guard', 'sql', 'query', 'db', 'database', 'api',
  'route', 'controller', 'handler', 'upload', 'payment', 'billing', 'webhook',
  'cookie', 'cors', 'csrf', 'sanitize', 'validate',
];

const ENTRY_HINTS = ['index', 'main', 'app', 'server', 'router', 'routes'];

type Candidate = { rel: string; abs: string; bytes: number; reason: string; weight: number };

export type ReviewFile = { path: string; reason: string; content: string };

export type ChecklistSection = { title: string; items: string[] };

export type CodeReviewBundle = {
  root: string;
  projectType: ProjectType;
  files: ReviewFile[];
  truncated: boolean;
  checklist: { sections: ChecklistSection[] };
  instructions: string;
};

function rankFile(rel: string, bytes: number): { weight: number; reason: string } {
  const lower = rel.toLowerCase();
  const base = path.basename(lower).replace(/\.[^.]+$/, '');
  let weight = 0;
  const reasons: string[] = [];

  const isTest = /\.(test|spec)\./.test(lower) || /(^|[\\/])(test|tests|__tests__)([\\/]|$)/.test(lower);
  if (isTest) weight -= 5; // tests are evidence elsewhere; not the read target

  const secHits = SECURITY_HINTS.filter((h) => lower.includes(h)).length;
  if (secHits > 0) {
    weight += 6 + secHits;
    reasons.push('security-relevant path');
  }
  if (ENTRY_HINTS.includes(base)) {
    weight += 4;
    reasons.push('entry point');
  }
  // Bigger files carry more architecture signal, with diminishing return.
  weight += Math.min(5, Math.floor(bytes / 4000));
  if (bytes > 12000) reasons.push('large file');

  return { weight, reason: reasons.join(', ') || 'general' };
}

async function collect(absRoot: string): Promise<Candidate[]> {
  const out: Candidate[] = [];
  async function walk(dir: string): Promise<void> {
    let entries: import('node:fs').Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.git')) await walk(path.join(dir, e.name));
        continue;
      }
      if (!e.isFile()) continue;
      const ext = path.extname(e.name).toLowerCase();
      if (!SOURCE_EXTS.has(ext)) continue;
      const abs = path.join(dir, e.name);
      let bytes = 0;
      try {
        bytes = (await fs.stat(abs)).size;
      } catch {
        continue;
      }
      const rel = path.relative(absRoot, abs);
      const { weight, reason } = rankFile(rel, bytes);
      out.push({ rel, abs, bytes, reason, weight });
    }
  }
  await walk(absRoot);
  return out;
}

// Named exploit classes every review must cover (spec §4a). Static analysis:
// identify the exploitable pattern in code; we do not run live payloads.
const UNIVERSAL_SECURITY: string[] = [
  'Auth / login: is authentication present where required and done safely (no homemade crypto, safe session/JWT handling, rate-limited login, sound password reset)?',
  'Access control / IDOR (BOLA): does every privileged action verify the caller OWNS the resource, not just that they are logged in? (The top real-world breach class.)',
  'Injection: are queries parameterized and inputs kept out of code paths (SQL, NoSQL, command, path traversal, template)?',
  'Sensitive data / leaks: any secrets, DB connection strings, or keys in code or a committed .env? Any endpoint returning passwords or PII? Secrets leaked in logs or errors?',
  'Unsafe dynamic execution (eval, deserialization).',
];

const ARCHITECTURE: string[] = [
  'Separation of concerns; coupling and cohesion; god-files and god-functions.',
  'Consistent patterns; testability (injectable dependencies, isolated side effects).',
  'Dead code, duplication, copy-paste drift.',
];

const PLATFORM_SECTION: Record<ProjectType, ChecklistSection | null> = {
  'ai-agent': {
    title: 'AI-agent / LLM security (weight this highest)',
    items: [
      'Are external content and tool outputs, INCLUDING ERRORS, treated as data, never as instructions to act?',
      'Excessive agency: can a tool output trigger install / exec / network / file-write with no human gate?',
      'Does the agent hold a general "run anything" capability, or only typed, scoped actions?',
      'Are secrets (SSH keys, cloud credentials, .env) reachable from the agent execution context?',
      'Prompt injection (direct and indirect); insecure tool / MCP design; sensitive-info disclosure in outputs.',
    ],
  },
  web: {
    title: 'Web security',
    items: [
      'XSS: is output encoded / escaped in the rendered context?',
      'CSRF protection on state-changing requests.',
      'SSRF on any server-side fetch of user-supplied URLs.',
      'Security headers and misconfiguration; secrets exposed in the client bundle.',
    ],
  },
  api: {
    title: 'API security',
    items: [
      'BOLA / IDOR and broken object/property-level authorization.',
      'Mass assignment (binding untrusted fields to models).',
      'Missing rate limiting; excessive data exposure in responses.',
    ],
  },
  mobile: {
    title: 'Mobile security',
    items: [
      'Insecure local storage of sensitive data; hardcoded keys.',
      'Missing certificate pinning; exported components and deep-link handling.',
    ],
  },
  cli: null,
  library: null,
  unknown: null,
};

/** Build a checklist tailored to the project type. AI-agent leads with its section. */
export function buildChecklist(projectType: ProjectType): { sections: ChecklistSection[] } {
  const sections: ChecklistSection[] = [];
  const platform = PLATFORM_SECTION[projectType];
  if (projectType === 'ai-agent' && platform) sections.push(platform);
  sections.push({ title: 'Security (universal)', items: UNIVERSAL_SECURITY });
  if (projectType !== 'ai-agent' && platform) sections.push(platform);
  sections.push({ title: 'Architecture', items: ARCHITECTURE });
  return { sections };
}

const INSTRUCTIONS = [
  'Read the files above. Assess only what the code shows; do not assume.',
  'Return a JSON object shaped exactly like this, then call score_build_readiness with it as the `qualitative` argument (along with path, stage, and any test numbers):',
  '',
  '{',
  '  "security": { "rating": 0-100, "findings": ["..."], "risks": [{ "title": "...", "severity": "critical|high|medium|low", "fix": "..." }] },',
  '  "architecture": { "rating": 0-100, "findings": ["..."], "risks": [{ "title": "...", "severity": "critical|high|medium|low", "fix": "..." }] }',
  '}',
  '',
  'Rating guidance: 90+ means a technical reviewer would find little to flag; 50 means real gaps; below 40 means serious problems. Grade honestly against the project stage.',
].join('\n');

export type PrepareCodeReviewOptions = {
  projectType?: ProjectType;
  maxFiles?: number;
  maxBytes?: number;
  maxBytesPerFile?: number;
};

/** Build a code-review bundle: the highest-signal files plus a type-aware checklist. */
export async function prepareCodeReview(
  root: string,
  options: PrepareCodeReviewOptions = {},
): Promise<CodeReviewBundle> {
  const {
    projectType = 'unknown',
    maxFiles = 14,
    maxBytes = 90_000,
    maxBytesPerFile = 12_000,
  } = options;
  const absRoot = path.resolve(root);
  const candidates = (await collect(absRoot)).sort((a, b) => b.weight - a.weight);

  const files: ReviewFile[] = [];
  let used = 0;
  let truncated = false;
  for (const c of candidates) {
    if (files.length >= maxFiles) {
      truncated = true;
      break;
    }
    if (used >= maxBytes) {
      truncated = true;
      break;
    }
    let content = '';
    try {
      content = await fs.readFile(c.abs, 'utf8');
    } catch {
      continue;
    }
    // Cap each file so one large file cannot starve coverage of the rest.
    const perFile = Math.min(maxBytesPerFile, maxBytes - used);
    if (content.length > perFile) {
      content = content.slice(0, perFile) + '\n... [truncated; showing the first part for review]';
      truncated = true;
    }
    used += content.length;
    files.push({ path: c.rel, reason: c.reason, content });
  }

  return {
    root: absRoot,
    projectType,
    files,
    truncated,
    checklist: buildChecklist(projectType),
    instructions: INSTRUCTIONS,
  };
}
