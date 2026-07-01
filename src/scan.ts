/**
 * Local project scanner — the part of Obra CTO that touches your code.
 *
 * It runs on your machine, reads files under the project root, and returns
 * MECHANICAL SIGNALS only: counts, presence flags, framework guesses, and
 * redacted secret-pattern hits. It never returns your source, and nothing here
 * sends data anywhere. The signals are what the scorer reasons over.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';

/** Directories we never descend into. */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  'coverage',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  '.turbo',
  '.cache',
]);

const SOURCE_EXTS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.rs', '.java', '.rb', '.php', '.cs',
  '.vue', '.svelte', '.c', '.cpp', '.h', '.hpp', '.swift', '.kt',
  // Data / policy layer. For BaaS apps (Supabase, Firebase, Prisma) the real
  // security surface lives here, not in the UI code.
  '.sql', '.prisma', '.graphql',
]);

export type ProjectSignals = {
  root: string;
  fileCount: number;
  sourceFileCount: number;
  totalLoc: number;
  languages: Record<string, number>;
  hasReadme: boolean;
  hasLicense: boolean;
  manifest: {
    ecosystem: 'node' | 'python' | 'rust' | 'go' | 'unknown';
    name: string | null;
    dependencyCount: number;
    dependencyNames: string[];
    scripts: string[];
    hasLockfile: boolean;
    hasBin: boolean;
  };
  tests: {
    present: boolean;
    framework: string | null;
    testFileCount: number;
    testCommand: string | null;
  };
  ci: { present: boolean; files: string[] };
  committedEnvFile: boolean;
  secrets: { suspectCount: number; locations: string[] };
  todos: number;
  largestSourceFiles: { path: string; loc: number }[];
  /** Detected primary project type, used to pick the right threat lens. */
  projectType: ProjectType;
  /** Recognised frameworks/SDKs found in the dependencies (for display). */
  frameworks: string[];
  /**
   * Backend-as-a-Service platforms detected (Supabase, Firebase, ...). For these,
   * the data is protected only by the platform's access rules (RLS / security
   * rules), so those rules are the security surface, not the client code.
   */
  backends: string[];
  suggestedStage: BuildStage;
};

export type BuildStage = 'prototype' | 'mvp' | 'growth';

export type ProjectType =
  | 'ai-agent'
  | 'web'
  | 'api'
  | 'mobile'
  | 'cli'
  | 'library'
  | 'unknown';

/** Dependency-name signals per type. Lowercased substrings matched against deps. */
const TYPE_DEPS: { type: ProjectType; deps: string[] }[] = [
  {
    type: 'ai-agent',
    deps: [
      '@modelcontextprotocol/sdk', 'openai', '@anthropic-ai/sdk', '@anthropic-ai/claude-code',
      'langchain', '@langchain/core', 'langgraph', 'llamaindex', 'llama-index', 'crewai',
      'autogen', 'ollama', '@google/generative-ai', 'google-generativeai', 'cohere-ai',
      'litellm', 'transformers', 'anthropic', 'ai',
    ],
  },
  { type: 'mobile', deps: ['react-native', 'expo', '@ionic/core', 'nativescript'] },
  {
    type: 'web',
    deps: ['react', 'react-dom', 'next', 'vue', 'svelte', '@angular/core', 'solid-js', 'astro', 'nuxt', '@remix-run/react', 'gatsby'],
  },
  {
    type: 'api',
    deps: ['express', 'fastify', 'koa', '@nestjs/core', 'hapi', 'flask', 'django', 'fastapi', 'starlette'],
  },
  { type: 'cli', deps: ['commander', 'yargs', 'oclif', '@oclif/core', 'inquirer', 'clipanion'] },
];

/**
 * Backend-as-a-Service SDKs. When present, the app's data is guarded by the
 * platform's access rules (Supabase RLS, Firebase security rules), not by the
 * client. Detecting one flips on the BaaS security lens in the code review.
 */
const BACKEND_DEPS: { name: string; deps: string[] }[] = [
  { name: 'supabase', deps: ['@supabase/supabase-js', '@supabase/auth-helpers-nextjs', '@supabase/ssr'] },
  { name: 'firebase', deps: ['firebase', 'firebase-admin', '@firebase/app', '@angular/fire', 'react-native-firebase'] },
  { name: 'appwrite', deps: ['appwrite', 'node-appwrite'] },
  { name: 'pocketbase', deps: ['pocketbase'] },
  { name: 'convex', deps: ['convex'] },
  { name: 'amplify', deps: ['aws-amplify', '@aws-amplify/core'] },
];

/** Detect BaaS platforms from dependency names (exact match). */
export function detectBackends(depNames: string[]): string[] {
  const names = new Set(depNames.map((d) => d.toLowerCase()));
  const found: string[] = [];
  for (const { name, deps } of BACKEND_DEPS) {
    if (deps.some((d) => names.has(d.toLowerCase()))) found.push(name);
  }
  return found;
}

const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'aws_access_key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'openai_key', re: /sk-[A-Za-z0-9]{20,}/ },
  { name: 'private_key_block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { name: 'generic_secret_assignment', re: /(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i },
  { name: 'slack_token', re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
];

async function listDir(dir: string): Promise<{ files: string[]; dirs: string[] }> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  const dirs: string[] = [];
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.git')) dirs.push(e.name);
    } else if (e.isFile()) {
      files.push(e.name);
    }
  }
  return { files, dirs };
}

function looksLikeTest(rel: string): boolean {
  const base = path.basename(rel).toLowerCase();
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(base)) return true;
  if (/_test\.py$/.test(base) || /^test_.*\.py$/.test(base)) return true;
  const parts = rel.split(/[\\/]/).map((p) => p.toLowerCase());
  return parts.includes('__tests__') || parts.includes('test') || parts.includes('tests');
}

function countLines(content: string): number {
  if (content.length === 0) return 0;
  let n = 1;
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) n++;
  return n;
}

/** Scan a project root and return mechanical signals. */
export async function scanProject(root: string): Promise<ProjectSignals> {
  const absRoot = path.resolve(root);
  const languages: Record<string, number> = {};
  const largest: { path: string; loc: number }[] = [];
  let fileCount = 0;
  let sourceFileCount = 0;
  let totalLoc = 0;
  let testFileCount = 0;
  let todos = 0;
  const secretLocations: string[] = [];
  const ciFiles: string[] = [];
  let committedEnvFile = false;

  async function walk(dir: string): Promise<void> {
    let listing: { files: string[]; dirs: string[] };
    try {
      listing = await listDir(dir);
    } catch {
      return;
    }
    for (const f of listing.files) {
      fileCount++;
      const abs = path.join(dir, f);
      const rel = path.relative(absRoot, abs);
      if (/^\.env(\.|$)/.test(f) && !/\.example$/.test(f) && !/\.sample$/.test(f)) {
        committedEnvFile = true;
      }
      const ext = path.extname(f).toLowerCase();
      if (!SOURCE_EXTS.has(ext)) continue;
      sourceFileCount++;
      languages[ext] = (languages[ext] ?? 0) + 1;
      if (looksLikeTest(rel)) testFileCount++;
      let content = '';
      try {
        content = await fs.readFile(abs, 'utf8');
      } catch {
        continue;
      }
      const loc = countLines(content);
      totalLoc += loc;
      largest.push({ path: rel, loc });
      const todoMatches = content.match(/\b(TODO|FIXME|HACK|XXX)\b/g);
      if (todoMatches) todos += todoMatches.length;
      for (const p of SECRET_PATTERNS) {
        if (p.re.test(content)) secretLocations.push(`${rel} (${p.name})`);
      }
    }
    for (const d of listing.dirs) {
      await walk(path.join(dir, d));
    }
  }

  await walk(absRoot);

  // Top-level marker files.
  let topFiles: string[] = [];
  try {
    topFiles = (await fs.readdir(absRoot, { withFileTypes: true }))
      .filter((e) => e.isFile())
      .map((e) => e.name);
  } catch {
    /* ignore */
  }
  const lower = new Set(topFiles.map((f) => f.toLowerCase()));
  const hasReadme = [...lower].some((f) => f.startsWith('readme'));
  const hasLicense = [...lower].some((f) => f.startsWith('license') || f.startsWith('licence'));

  // CI detection.
  for (const ci of ['.gitlab-ci.yml', 'azure-pipelines.yml', '.travis.yml']) {
    if (lower.has(ci)) ciFiles.push(ci);
  }
  try {
    const wf = path.join(absRoot, '.github', 'workflows');
    const entries = await fs.readdir(wf);
    for (const e of entries) if (/\.(ya?ml)$/.test(e)) ciFiles.push(`.github/workflows/${e}`);
  } catch {
    /* no workflows dir */
  }
  try {
    await fs.access(path.join(absRoot, '.circleci', 'config.yml'));
    ciFiles.push('.circleci/config.yml');
  } catch {
    /* none */
  }

  const manifest = await readManifest(absRoot, lower);
  const tests = inferTests(manifest, testFileCount);

  const { type: projectType, frameworks } = detectProjectType(manifest.dependencyNames, {
    hasBin: manifest.hasBin,
    hasTsx: (languages['.tsx'] ?? 0) > 0 || (languages['.jsx'] ?? 0) > 0 || (languages['.vue'] ?? 0) > 0 || (languages['.svelte'] ?? 0) > 0,
    hasPubspec: lower.has('pubspec.yaml'),
    ecosystemKnown: manifest.ecosystem !== 'unknown',
  });

  largest.sort((a, b) => b.loc - a.loc);

  const signals: ProjectSignals = {
    root: absRoot,
    fileCount,
    sourceFileCount,
    totalLoc,
    languages,
    hasReadme,
    hasLicense,
    manifest,
    tests,
    ci: { present: ciFiles.length > 0, files: ciFiles },
    committedEnvFile,
    secrets: { suspectCount: secretLocations.length, locations: secretLocations.slice(0, 20) },
    todos,
    largestSourceFiles: largest.slice(0, 5),
    projectType,
    frameworks,
    backends: detectBackends(manifest.dependencyNames),
    suggestedStage: 'mvp',
  };
  signals.suggestedStage = suggestStage(signals);
  return signals;
}

async function readManifest(
  absRoot: string,
  lower: Set<string>,
): Promise<ProjectSignals['manifest']> {
  // Node.
  if (lower.has('package.json')) {
    try {
      const raw = await fs.readFile(path.join(absRoot, 'package.json'), 'utf8');
      const pkg = JSON.parse(raw) as {
        name?: string;
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        scripts?: Record<string, string>;
        bin?: unknown;
      };
      const depNames = [
        ...Object.keys(pkg.dependencies ?? {}),
        ...Object.keys(pkg.devDependencies ?? {}),
      ];
      const hasLockfile =
        lower.has('package-lock.json') || lower.has('pnpm-lock.yaml') || lower.has('yarn.lock');
      return {
        ecosystem: 'node',
        name: pkg.name ?? null,
        dependencyCount: depNames.length,
        dependencyNames: depNames,
        scripts: Object.keys(pkg.scripts ?? {}),
        hasLockfile,
        hasBin: pkg.bin !== undefined,
      };
    } catch {
      /* fall through */
    }
  }
  if (lower.has('pyproject.toml') || lower.has('requirements.txt')) {
    let depNames: string[] = [];
    if (lower.has('requirements.txt')) {
      try {
        const raw = await fs.readFile(path.join(absRoot, 'requirements.txt'), 'utf8');
        depNames = raw
          .split('\n')
          .map((l) => l.trim())
          .filter((l) => l && !l.startsWith('#'))
          .map((l) => l.split(/[=<>!~\[ ]/)[0].trim().toLowerCase())
          .filter(Boolean);
      } catch {
        /* ignore */
      }
    }
    return {
      ecosystem: 'python',
      name: null,
      dependencyCount: depNames.length,
      dependencyNames: depNames,
      scripts: [],
      hasLockfile: lower.has('poetry.lock') || lower.has('pipfile.lock'),
      hasBin: false,
    };
  }
  if (lower.has('cargo.toml')) {
    return { ecosystem: 'rust', name: null, dependencyCount: 0, dependencyNames: [], scripts: [], hasLockfile: lower.has('cargo.lock'), hasBin: false };
  }
  if (lower.has('go.mod')) {
    return { ecosystem: 'go', name: null, dependencyCount: 0, dependencyNames: [], scripts: [], hasLockfile: lower.has('go.sum'), hasBin: false };
  }
  return { ecosystem: 'unknown', name: null, dependencyCount: 0, dependencyNames: [], scripts: [], hasLockfile: false, hasBin: false };
}

/**
 * Detect the primary project type from dependency names plus a few file signals.
 * Priority favors the most security-relevant lens: a web app that also calls an LLM
 * is treated as an ai-agent (its highest-risk surface), with both kept in frameworks.
 */
export function detectProjectType(
  depNames: string[],
  opts: { hasBin: boolean; hasTsx: boolean; hasPubspec: boolean; ecosystemKnown: boolean },
): { type: ProjectType; frameworks: string[] } {
  const names = new Set(depNames.map((d) => d.toLowerCase()));
  // Exact match only. Substring matching is unsafe here: 'react-native' contains
  // 'react', which would wrongly flag a plain React web app as mobile.
  const has = (dep: string): boolean => names.has(dep.toLowerCase());

  const frameworks: string[] = [];
  let detected: ProjectType | null = null;
  for (const { type, deps } of TYPE_DEPS) {
    const hits = deps.filter((d) => has(d));
    if (hits.length > 0) {
      frameworks.push(...hits);
      if (detected === null) detected = type; // first match wins (priority order)
    }
  }

  if (opts.hasPubspec && detected === null) detected = 'mobile';
  if (opts.hasTsx && detected === null) detected = 'web';
  if (opts.hasBin && detected === null) detected = 'cli';

  let type: ProjectType;
  if (detected !== null) type = detected;
  else if (opts.ecosystemKnown) type = 'library';
  else type = 'unknown';

  return { type, frameworks: [...new Set(frameworks)] };
}

function inferTests(
  manifest: ProjectSignals['manifest'],
  testFileCount: number,
): ProjectSignals['tests'] {
  let framework: string | null = null;
  let testCommand: string | null = null;
  if (manifest.ecosystem === 'node') {
    if (manifest.scripts.includes('test')) testCommand = 'npm test';
  } else if (manifest.ecosystem === 'python') {
    framework = 'pytest';
    testCommand = 'pytest';
  }
  return {
    present: testFileCount > 0,
    framework,
    testFileCount,
    testCommand,
  };
}

function suggestStage(s: ProjectSignals): BuildStage {
  // Coarse heuristic; the user can override at scoring time.
  if (s.totalLoc < 2000 && !s.tests.present) return 'prototype';
  if (s.ci.present && s.tests.present && s.totalLoc > 8000) return 'growth';
  return 'mvp';
}
