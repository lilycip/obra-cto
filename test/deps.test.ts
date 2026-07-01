import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseNpmLockfile, queryOsvBatch, checkDependencies, type Pkg } from '../src/deps.js';

const SAMPLE_LOCK = JSON.stringify({
  name: 'demo',
  lockfileVersion: 3,
  packages: {
    '': { name: 'demo', version: '1.0.0' },
    'node_modules/left-pad': { version: '1.3.0' },
    'node_modules/express': { version: '4.17.1' },
    'node_modules/@scope/pkg': { version: '2.0.0' },
    'node_modules/express/node_modules/left-pad': { version: '1.3.0' }, // dup name@version
  },
});

describe('parseNpmLockfile', () => {
  it('extracts name@version pairs and skips the root', () => {
    const pkgs = parseNpmLockfile(SAMPLE_LOCK);
    const ids = pkgs.map((p) => `${p.name}@${p.version}`);
    expect(ids).toContain('left-pad@1.3.0');
    expect(ids).toContain('express@4.17.1');
    expect(ids).toContain('@scope/pkg@2.0.0');
    expect(ids).not.toContain('demo@1.0.0'); // root excluded
  });

  it('dedups identical name@version across nesting', () => {
    const pkgs = parseNpmLockfile(SAMPLE_LOCK);
    expect(pkgs.filter((p) => p.name === 'left-pad').length).toBe(1);
  });

  it('returns empty on malformed JSON', () => {
    expect(parseNpmLockfile('{not json')).toEqual([]);
  });
});

describe('queryOsvBatch', () => {
  it('maps OSV results back to the input packages by index', async () => {
    const pkgs: Pkg[] = [
      { name: 'safe-pkg', version: '1.0.0' },
      { name: 'bad-pkg', version: '0.1.0' },
    ];
    const fakeFetch = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ results: [{}, { vulns: [{ id: 'GHSA-xxxx' }, { id: 'CVE-2026-1' }] }] }),
    });
    const vulnerable = await queryOsvBatch(pkgs, 'npm', fakeFetch);
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toEqual({ name: 'bad-pkg', version: '0.1.0', vulnIds: ['GHSA-xxxx', 'CVE-2026-1'] });
  });

  it('throws on a non-ok OSV response', async () => {
    const fakeFetch = async () => ({ ok: false, status: 500, json: async () => ({}) });
    await expect(queryOsvBatch([{ name: 'x', version: '1' }], 'npm', fakeFetch)).rejects.toThrow(/500/);
  });
});

describe('checkDependencies', () => {
  let root: string;
  beforeAll(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'obra-cto-deps-'));
    await fs.writeFile(path.join(root, 'package-lock.json'), SAMPLE_LOCK, 'utf8');
  });
  afterAll(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  it('reports vulnerable packages from a lockfile via an injected fetch', async () => {
    const fakeFetch = async () => ({
      ok: true,
      status: 200,
      // 3 deps in order: left-pad, express, @scope/pkg → mark express vulnerable.
      json: async () => ({ results: [{}, { vulns: [{ id: 'CVE-2026-9' }] }, {}] }),
    });
    const res = await checkDependencies(root, { fetchImpl: fakeFetch });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.ecosystem).toBe('npm');
      expect(res.checked).toBe(3);
      expect(res.vulnerable.map((v) => v.name)).toContain('express');
    }
  });

  it('fails gracefully when there is no lockfile', async () => {
    const empty = await fs.mkdtemp(path.join(os.tmpdir(), 'obra-cto-nolock-'));
    const res = await checkDependencies(empty, { fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({}) }) });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/lockfile|package-lock/i);
    await fs.rm(empty, { recursive: true, force: true });
  });
});
