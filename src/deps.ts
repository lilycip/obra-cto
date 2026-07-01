/**
 * Dependency CVE check via OSV.dev.
 *
 * Reads exact versions from the lockfile and queries the OSV batch API for known
 * vulnerabilities. Only package names and versions leave the machine (those are not
 * secrets); your source never does. OSV is the canonical, always-current feed, so we
 * do not maintain our own database.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';

export type Pkg = { name: string; version: string };
export type OsvEcosystem = 'npm' | 'PyPI';

export type VulnerablePackage = { name: string; version: string; vulnIds: string[] };

export type DependencyCheck =
  | {
      ok: true;
      ecosystem: OsvEcosystem;
      checked: number;
      vulnerable: VulnerablePackage[];
    }
  | { ok: false; reason: string };

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}>;

/** Parse exact name@version pairs from an npm package-lock.json (v2/v3). */
export function parseNpmLockfile(content: string): Pkg[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  const pkgs = (parsed as { packages?: Record<string, { version?: string }> }).packages;
  if (!pkgs || typeof pkgs !== 'object') return [];
  const seen = new Set<string>();
  const out: Pkg[] = [];
  for (const [key, meta] of Object.entries(pkgs)) {
    if (key === '') continue; // the root project
    const idx = key.lastIndexOf('node_modules/');
    if (idx === -1) continue;
    const name = key.slice(idx + 'node_modules/'.length);
    const version = meta?.version;
    if (!name || !version) continue;
    const id = `${name}@${version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ name, version });
  }
  return out;
}

/** Query the OSV batch API. Returns vuln IDs per input package (aligned by index). */
export async function queryOsvBatch(
  pkgs: Pkg[],
  ecosystem: OsvEcosystem,
  fetchImpl: FetchLike,
): Promise<VulnerablePackage[]> {
  const vulnerable: VulnerablePackage[] = [];
  // OSV batch accepts up to 1000 queries; chunk to be safe.
  const CHUNK = 500;
  for (let i = 0; i < pkgs.length; i += CHUNK) {
    const slice = pkgs.slice(i, i + CHUNK);
    const body = JSON.stringify({
      queries: slice.map((p) => ({ package: { name: p.name, ecosystem }, version: p.version })),
    });
    const res = await fetchImpl('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    });
    if (!res.ok) throw new Error(`OSV returned ${res.status}`);
    const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
    const results = data.results ?? [];
    results.forEach((r, j) => {
      const ids = (r.vulns ?? []).map((v) => v.id);
      if (ids.length > 0) {
        const p = slice[j];
        vulnerable.push({ name: p.name, version: p.version, vulnIds: ids });
      }
    });
  }
  return vulnerable;
}

/** Check a project's locked dependencies against OSV. */
export async function checkDependencies(
  root: string,
  opts: { fetchImpl?: FetchLike } = {},
): Promise<DependencyCheck> {
  const absRoot = path.resolve(root);
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) return { ok: false, reason: 'No fetch available in this runtime (needs Node 18+).' };

  // npm first (dominant for our audience).
  let lockContent: string | null = null;
  try {
    lockContent = await fs.readFile(path.join(absRoot, 'package-lock.json'), 'utf8');
  } catch {
    lockContent = null;
  }
  if (lockContent === null) {
    return {
      ok: false,
      reason: 'No package-lock.json found. Exact versions are needed for accurate CVE matching; commit a lockfile or run the check against a project that has one.',
    };
  }

  const pkgs = parseNpmLockfile(lockContent);
  if (pkgs.length === 0) return { ok: false, reason: 'Could not read dependencies from package-lock.json.' };

  try {
    const vulnerable = await queryOsvBatch(pkgs, 'npm', fetchImpl);
    return { ok: true, ecosystem: 'npm', checked: pkgs.length, vulnerable };
  } catch (err) {
    return { ok: false, reason: `OSV query failed: ${(err as Error).message}` };
  }
}
