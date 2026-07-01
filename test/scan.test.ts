import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { scanProject, detectProjectType, detectBackends } from '../src/scan.js';

let root: string;

async function write(rel: string, content: string): Promise<void> {
  const abs = path.join(root, rel);
  await fs.mkdir(path.dirname(abs), { recursive: true });
  await fs.writeFile(abs, content, 'utf8');
}

beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'obra-cto-scan-'));
  await write(
    'package.json',
    JSON.stringify({
      name: 'fix',
      dependencies: { 'left-pad': '1.0.0' },
      devDependencies: { vitest: '2.0.0' },
      scripts: { test: 'vitest', build: 'tsc' },
    }),
  );
  await write('package-lock.json', '{}');
  await write('README.md', '# fix');
  await write('LICENSE', 'MIT');
  await write('src/index.ts', 'export const x = 1;\n// TODO: tidy this up\n');
  await write('src/auth.ts', 'export function login() { return true; }\n');
  await write('src/foo.test.ts', 'import { it } from "vitest"; it("x", () => {});\n');
  await write('.env', 'SECRET=supersecretvalue\n');
  // Build the fake key from pieces so this source file does not itself contain a
  // secret-shaped literal (which would otherwise trip the scanner on a self-scan).
  const fakeKey = 'sk-' + 'a'.repeat(30);
  await write('src/leak.ts', `const k = "${fakeKey}";\n`);
  await write('.github/workflows/ci.yml', 'name: ci\non: [push]\n');
  // node_modules content must be ignored:
  await write('node_modules/junk/index.ts', 'export const ignored = 1;\n');
});

afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true });
});

describe('scanProject', () => {
  it('detects the node manifest, deps, scripts, and lockfile', async () => {
    const s = await scanProject(root);
    expect(s.manifest.ecosystem).toBe('node');
    expect(s.manifest.name).toBe('fix');
    expect(s.manifest.dependencyCount).toBe(2);
    expect(s.manifest.scripts).toEqual(expect.arrayContaining(['test', 'build']));
    expect(s.manifest.hasLockfile).toBe(true);
  });

  it('detects docs, tests, and CI', async () => {
    const s = await scanProject(root);
    expect(s.hasReadme).toBe(true);
    expect(s.hasLicense).toBe(true);
    expect(s.tests.present).toBe(true);
    expect(s.tests.testFileCount).toBeGreaterThanOrEqual(1);
    expect(s.tests.testCommand).toBe('npm test');
    expect(s.ci.present).toBe(true);
    expect(s.ci.files).toEqual(expect.arrayContaining(['.github/workflows/ci.yml']));
  });

  it('flags a committed .env and a hardcoded secret', async () => {
    const s = await scanProject(root);
    expect(s.committedEnvFile).toBe(true);
    expect(s.secrets.suspectCount).toBeGreaterThanOrEqual(1);
  });

  it('counts source files, ignores node_modules, and finds TODO markers', async () => {
    const s = await scanProject(root);
    // index, auth, foo.test, leak = 4 source files; node_modules ignored.
    expect(s.sourceFileCount).toBe(4);
    expect(s.todos).toBeGreaterThanOrEqual(1);
  });

  it('classifies the dependency-light fixture as a library', async () => {
    const s = await scanProject(root);
    // deps are left-pad + vitest; no framework, no .tsx, no bin → library.
    expect(s.projectType).toBe('library');
  });

  it('does not flag a .env.example as a committed env file', async () => {
    const clean = await fs.mkdtemp(path.join(os.tmpdir(), 'obra-cto-clean-'));
    await fs.writeFile(path.join(clean, '.env.example'), 'SECRET=\n', 'utf8');
    await fs.writeFile(path.join(clean, 'package.json'), '{"name":"c"}', 'utf8');
    const s = await scanProject(clean);
    expect(s.committedEnvFile).toBe(false);
    await fs.rm(clean, { recursive: true, force: true });
  });
});

describe('detectProjectType', () => {
  const opts = { hasBin: false, hasTsx: false, hasPubspec: false, ecosystemKnown: true };

  it('detects ai-agent from an MCP/LLM SDK', () => {
    expect(detectProjectType(['@modelcontextprotocol/sdk', 'zod'], opts).type).toBe('ai-agent');
    expect(detectProjectType(['openai'], opts).type).toBe('ai-agent');
    expect(detectProjectType(['@anthropic-ai/sdk', 'langchain'], opts).type).toBe('ai-agent');
  });

  it('prefers ai-agent even when web deps are also present (highest-risk lens)', () => {
    const r = detectProjectType(['next', 'react', 'openai'], opts);
    expect(r.type).toBe('ai-agent');
    expect(r.frameworks).toEqual(expect.arrayContaining(['openai', 'next', 'react']));
  });

  it('detects web, api, mobile, cli', () => {
    expect(detectProjectType(['react', 'react-dom'], opts).type).toBe('web');
    expect(detectProjectType(['express'], opts).type).toBe('api');
    expect(detectProjectType(['react-native'], opts).type).toBe('mobile');
    expect(detectProjectType(['commander'], opts).type).toBe('cli');
  });

  it('falls back to bin/tsx/pubspec file signals when no deps match', () => {
    expect(detectProjectType([], { ...opts, hasBin: true }).type).toBe('cli');
    expect(detectProjectType([], { ...opts, hasTsx: true }).type).toBe('web');
    expect(detectProjectType([], { ...opts, hasPubspec: true }).type).toBe('mobile');
  });

  it('is library when a manifest exists but nothing matches, unknown otherwise', () => {
    expect(detectProjectType(['left-pad'], opts).type).toBe('library');
    expect(detectProjectType([], { ...opts, ecosystemKnown: false }).type).toBe('unknown');
  });
});

describe('detectBackends', () => {
  it('detects Supabase and Firebase from their SDKs', () => {
    expect(detectBackends(['@supabase/supabase-js', 'react'])).toContain('supabase');
    expect(detectBackends(['firebase'])).toContain('firebase');
    expect(detectBackends(['react-native-firebase'])).toContain('firebase');
  });

  it('returns an empty list when no BaaS SDK is present', () => {
    expect(detectBackends(['express', 'left-pad'])).toEqual([]);
  });

  it('does not false-match on substrings', () => {
    // "firebase-tools-lookalike" is not the real SDK; exact-name match only.
    expect(detectBackends(['notfirebase', 'supabaseish'])).toEqual([]);
  });
});
