import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { prepareCodeReview, buildChecklist } from '../src/review.js';

let root: string;

beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'obra-cto-review-'));
  const w = (rel: string, content: string) => fs.writeFile(path.join(root, rel), content, 'utf8');
  await fs.mkdir(path.join(root, 'src'), { recursive: true });
  await w('src/auth.ts', 'export function login() {}\n'.repeat(20)); // security-named
  await w('src/index.ts', 'export const main = 1;\n'.repeat(20)); // entry point
  await w('src/util.ts', 'export const u = 1;\n'.repeat(20)); // general
  await w('src/huge.ts', '// big\n'.repeat(5000)); // ~35KB, must be capped
  await w('src/foo.test.ts', 'test stuff\n'.repeat(20)); // test, deprioritized
});

afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true });
});

describe('prepareCodeReview', () => {
  it('spreads coverage across files instead of letting one big file starve the rest', async () => {
    const bundle = await prepareCodeReview(root, { maxFiles: 14, maxBytes: 90_000, maxBytesPerFile: 12_000 });
    expect(bundle.files.length).toBeGreaterThanOrEqual(3);
  });

  it('caps each file so the huge file cannot eat the whole budget', async () => {
    const bundle = await prepareCodeReview(root, { maxFiles: 14, maxBytes: 90_000, maxBytesPerFile: 12_000 });
    const huge = bundle.files.find((f) => f.path.endsWith('huge.ts'));
    expect(huge).toBeDefined();
    // 12_000 cap plus the truncation marker line.
    expect(huge!.content.length).toBeLessThan(12_200);
    expect(bundle.truncated).toBe(true);
  });

  it('ranks the security-named file into the bundle', async () => {
    const bundle = await prepareCodeReview(root, { maxFiles: 14, maxBytes: 90_000, maxBytesPerFile: 12_000 });
    expect(bundle.files.some((f) => f.path.endsWith('auth.ts'))).toBe(true);
  });

  it('respects the total byte budget', async () => {
    const bundle = await prepareCodeReview(root, { maxFiles: 14, maxBytes: 30_000, maxBytesPerFile: 12_000 });
    const total = bundle.files.reduce((sum, f) => sum + f.content.length, 0);
    expect(total).toBeLessThanOrEqual(30_000);
  });

  it('returns non-empty checklist sections and instructions', async () => {
    const bundle = await prepareCodeReview(root, { maxFiles: 14 });
    expect(bundle.checklist.sections.length).toBeGreaterThan(0);
    expect(bundle.checklist.sections.every((s) => s.items.length > 0)).toBe(true);
    expect(bundle.instructions.length).toBeGreaterThan(0);
  });

  it('tailors the checklist to the project type passed in', async () => {
    const bundle = await prepareCodeReview(root, { maxFiles: 14, projectType: 'ai-agent' });
    expect(bundle.projectType).toBe('ai-agent');
    expect(bundle.checklist.sections[0].title).toMatch(/AI-agent/i);
  });
});

describe('buildChecklist', () => {
  it('leads with the AI-agent section for agent projects', () => {
    const cl = buildChecklist('ai-agent');
    expect(cl.sections[0].title).toMatch(/AI-agent/i);
  });

  it('puts universal security first, then the platform section, for non-agent types', () => {
    const web = buildChecklist('web');
    expect(web.sections[0].title).toMatch(/universal/i);
    expect(web.sections.some((s) => s.title === 'Web security')).toBe(true);
  });

  it('always includes Security and Architecture sections', () => {
    for (const t of ['web', 'api', 'mobile', 'cli', 'library', 'unknown', 'ai-agent'] as const) {
      const titles = buildChecklist(t).sections.map((s) => s.title);
      expect(titles.some((x) => /security/i.test(x))).toBe(true);
      expect(titles).toContain('Architecture');
    }
  });
});
