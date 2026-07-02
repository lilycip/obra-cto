/**
 * Malicious-repo detection — the tripwire that runs BEFORE you trust a repo.
 *
 * The Obra CTO can be pointed at a repository you did not write (to score a
 * stranger's project, or to inspect something suspicious). Reading a repo is
 * safe. Running its install scripts, its `postinstall` hook, or its test command
 * is NOT: that is the exact "clone-this-repo" remote-code-execution vector, where
 * a clean-looking project hides an obfuscated payload that decodes to an attacker
 * URL, fetches code, and executes it with your privileges the moment you install
 * or boot it (threat-lens TL-005).
 *
 * This module runs pure, static pattern checks over file contents that the scanner
 * has ALREADY read on your machine. It sends nothing anywhere. It never executes a
 * line of the code it inspects. Detection is deliberately COMBINATION-driven: a
 * lone `eval`, a lone `postinstall`, or a lone base64 string is common and benign,
 * so those alone do not raise the alarm. The signature we hunt is the CHAIN, for
 * example an obfuscated blob that gets decoded and then executed, or an install
 * hook that pipes the network into a shell. That keeps false positives low, which
 * matters: a tripwire that cries wolf gets ignored.
 *
 * All evidence strings are redacted (control characters stripped, whitespace
 * collapsed, length capped) before they leave this module, because they come from
 * an untrusted repo and are handed back to the host model. They are DATA, never
 * instructions.
 */

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';

export type ThreatFinding = {
  /** Stable identifier for the pattern class (e.g. 'dynamic-code-execution'). */
  id: string;
  title: string;
  severity: ThreatSeverity;
  /** Project-relative path of the file the finding is in. */
  file: string;
  /** 1-based line, best effort. */
  line?: number;
  /** Short, redacted snippet. Untrusted data, safe to display. */
  evidence: string;
  /** One line on why this pattern is dangerous. */
  why: string;
};

export type ThreatVerdict = 'clean' | 'suspicious' | 'dangerous';

export type ThreatScan = {
  verdict: ThreatVerdict;
  findings: ThreatFinding[];
  filesScanned: number;
};

/** File extensions whose contents we run the shell-oriented checks over. */
export const SCRIPT_EXTS = new Set(['.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd']);

/** npm lifecycle keys that run automatically on `npm install`. The RCE surface. */
const INSTALL_HOOK_KEYS = ['preinstall', 'install', 'postinstall', 'prepare'];

// ── Redaction ───────────────────────────────────────────────────────────────
// Evidence comes from an untrusted repo. Strip control characters (so a payload
// cannot smuggle terminal escapes or fake instructions), collapse whitespace, and
// cap length so we never echo a full base64 blob back.
function redact(raw: string, max = 120): string {
  let out = '';
  for (const ch of raw) {
    const c = ch.codePointAt(0) ?? 0;
    if (c === 9 || c === 32) out += ' ';
    else if (c < 32 || c === 127) out += ' ';
    else out += ch;
  }
  out = out.replace(/\s+/g, ' ').trim();
  if (out.length > max) out = out.slice(0, max) + '...';
  return out;
}

function lineAt(content: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) n++;
  }
  return n;
}

/** The single line of text containing `index`, redacted. */
function lineText(content: string, index: number): string {
  const start = content.lastIndexOf('\n', index - 1) + 1;
  let end = content.indexOf('\n', index);
  if (end === -1) end = content.length;
  return redact(content.slice(start, end));
}

function indicesOf(re: RegExp, content: string): number[] {
  const out: number[] = [];
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m: RegExpExecArray | null;
  while ((m = g.exec(content)) !== null) {
    out.push(m.index);
    if (m.index === g.lastIndex) g.lastIndex++; // guard against zero-width loops
  }
  return out;
}

function minDistance(a: number[], b: number[]): number {
  // Cap the arrays: a minified or hostile file could hold thousands of token hits,
  // and this is O(n*m). The nearest pair is what we want, so a sample suffices.
  const xs = a.slice(0, 200);
  const ys = b.slice(0, 200);
  let best = Infinity;
  for (const x of xs) {
    for (const y of ys) {
      const d = Math.abs(x - y);
      if (d < best) best = d;
    }
  }
  return best;
}

/**
 * Index of the first http(s) URL that points at a PUBLIC IPv4 literal. Loopback
 * and private ranges (127/8, 10/8, 192.168, 172.16-31, 0.0.0.0) are skipped so
 * ordinary local-dev fetches (http://127.0.0.1:3000) do not trip the tripwire.
 */
function firstPublicIpUrl(content: string): number | null {
  const re = /https?:\/\/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    const isPrivate =
      a === 127 || a === 10 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || a >= 224;
    if (!isPrivate) return m.index;
  }
  return null;
}

// ── Patterns ────────────────────────────────────────────────────────────────
// Dynamic code execution.
const EXEC_RE = /\beval\s*\(|new\s+Function\s*\(/;
// Obfuscated access to the same primitives: bracket access, comma-eval, or Function
// called directly with a string literal. These forms are almost never innocent.
const OBFUSCATED_EXEC_RE =
  /\[\s*['"](?:eval|Function)['"]\s*\]\s*\(|\(\s*0\s*,\s*eval\s*\)\s*\(|\bFunction\s*\(\s*['"`]|constructor\s*\(\s*['"`][^'"`]*\breturn\b/;
// Execution taking decoded data directly as its argument. Almost never legitimate.
const EXEC_OF_DECODE_RE =
  /(?:\beval|new\s+Function)\s*\(\s*(?:globalThis\.)?(?:atob|Buffer\.from|unescape|decodeURIComponent)/;
// Decoding of encoded data.
const DECODE_RE = /\batob\s*\(|Buffer\.from\s*\([^)]*['"]base64['"]|\bunescape\s*\(|base64\.b64decode\s*\(/;
// Network access.
const NET_RE =
  /\bfetch\s*\(|\brequire\s*\(\s*['"](?:node:)?https?['"]|\bhttps?\.get\s*\(|\bXMLHttpRequest\b|\baxios\b|\burllib\b|\brequests\.(?:get|post)\s*\(/;
// Shell / process spawning imported explicitly (the strong signal; a bare exec() is too common).
const CHILD_PROC_RE =
  /require\s*\(\s*['"](?:node:)?child_process['"]|from\s+['"](?:node:)?child_process['"]|import\s+subprocess\b|\bos\.system\s*\(/;
// Obfuscation blobs.
const BASE64_BLOB_RE = /['"`][A-Za-z0-9+/]{200,}={0,2}['"`]/;
const HEX_BLOB_RE = /(?:\\x[0-9a-fA-F]{2}){40,}|(?:\\u[0-9a-fA-F]{4}){40,}/;
const CHARCODE_RE = /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){20,}/;
// Known indicator of compromise from TL-005. Built from parts so this detector's
// own source does not contain the literal marker (which would make the CTO flag
// itself, and any security tool, as hostile on a self-scan).
const IOC_MARKER = 'ipcheck' + '-' + 'encrypted';
const IOC_RE = new RegExp(IOC_MARKER, 'i');

/**
 * Static malware scan of one source file. Returns at most one finding per pattern
 * class so a single file cannot flood the report. Combination-driven: severity
 * rises only when signals chain together.
 */
export function scanSourceFile(rel: string, content: string): ThreatFinding[] {
  const findings: ThreatFinding[] = [];

  const obfExec = OBFUSCATED_EXEC_RE.test(content);
  const execIdx = [...indicesOf(EXEC_RE, content), ...indicesOf(OBFUSCATED_EXEC_RE, content)].sort((a, b) => a - b);
  const decodeIdx = indicesOf(DECODE_RE, content);
  const netIdx = indicesOf(NET_RE, content);

  const hasDecode = decodeIdx.length > 0;
  const hasNet = netIdx.length > 0;

  // Dynamic code execution (one finding, highest applicable severity).
  if (execIdx.length > 0) {
    const directNest = EXEC_OF_DECODE_RE.test(content);
    const nearDecode = hasDecode && minDistance(execIdx, decodeIdx) <= 500;
    const nearNet = hasNet && minDistance(execIdx, netIdx) <= 500;

    let severity: ThreatSeverity;
    let why: string;
    if (directNest || nearDecode || nearNet) {
      severity = 'critical';
      why =
        'Executes code that is decoded or fetched at runtime. This is the core mechanism of a hidden-payload backdoor. Do not run this project until you understand this line.';
    } else if (hasDecode || hasNet) {
      severity = 'high';
      why =
        'Uses dynamic code execution in a file that also decodes data or calls the network. Review what it executes.';
    } else if (obfExec) {
      // Obfuscated access to eval/Function with no decode or network nearby is still
      // worse than a plain eval: hiding the call is the tell.
      severity = 'high';
      why = 'Reaches eval or Function through an obfuscated form (bracket access, comma-eval, or a string literal). Hiding the call is a red flag.';
    } else {
      severity = 'medium';
      why = 'Uses eval or new Function. Dynamic code execution is a code smell worth reviewing.';
    }
    findings.push({
      id: 'dynamic-code-execution',
      title: 'Dynamic code execution',
      severity,
      file: rel,
      line: lineAt(content, execIdx[0]),
      evidence: lineText(content, execIdx[0]),
      why,
    });
  }

  // Obfuscated blob (one finding).
  const blobIdx = [
    ...indicesOf(BASE64_BLOB_RE, content),
    ...indicesOf(HEX_BLOB_RE, content),
    ...indicesOf(CHARCODE_RE, content),
  ].sort((a, b) => a - b);
  if (blobIdx.length > 0) {
    let severity: ThreatSeverity;
    let why: string;
    if (hasDecode || execIdx.length > 0) {
      severity = 'high';
      why =
        'A large encoded blob sits alongside decoding or execution. This is how a payload is concealed then run. Read what it decodes to before trusting this file.';
    } else if (hasNet) {
      severity = 'medium';
      why = 'A large encoded blob sits alongside network calls. Review what it holds.';
    } else {
      severity = 'low';
      why =
        'A large encoded or obfuscated blob. It may be an inlined asset, or a concealed payload. Worth a look.';
    }
    findings.push({
      id: 'obfuscated-blob',
      title: 'Large obfuscated blob',
      severity,
      file: rel,
      line: lineAt(content, blobIdx[0]),
      evidence: lineText(content, blobIdx[0]),
      why,
    });
  }

  // Command execution combined with network or decoding (one finding). Kept at
  // medium, not high: legitimate build and deploy scripts pair child_process with
  // the network, so this surfaces for review rather than hard-blocking a run.
  const cpIdx = indicesOf(CHILD_PROC_RE, content);
  if (cpIdx.length > 0 && (hasNet || hasDecode)) {
    findings.push({
      id: 'command-execution',
      title: 'Command execution alongside network or decoding',
      severity: 'medium',
      file: rel,
      line: lineAt(content, cpIdx[0]),
      evidence: lineText(content, cpIdx[0]),
      why: hasNet
        ? 'Runs shell commands in a file that also calls the network. Check that no fetched value reaches the command.'
        : 'Runs shell commands using decoded input. Check where that input comes from.',
    });
  }

  // Known indicator of compromise.
  const iocIdx = indicesOf(IOC_RE, content);
  if (iocIdx.length > 0) {
    findings.push({
      id: 'ioc-endpoint',
      title: 'Known malicious endpoint marker',
      severity: 'critical',
      file: rel,
      line: lineAt(content, iocIdx[0]),
      evidence: lineText(content, iocIdx[0]),
      why: 'Contains a network-probe marker used by the clone-this-repo malware family (threat-lens TL-005). Treat this repo as hostile until proven otherwise.',
    });
  }

  // Hardcoded PUBLIC IP endpoint fetched at runtime (loopback/private skipped).
  const ipIdx = firstPublicIpUrl(content);
  if (ipIdx !== null && hasNet) {
    findings.push({
      id: 'hardcoded-ip',
      title: 'Hardcoded public IP endpoint',
      severity: 'medium',
      file: rel,
      line: lineAt(content, ipIdx),
      evidence: lineText(content, ipIdx),
      why: 'Reaches a raw public IP address rather than a named domain. Common in throwaway attacker infrastructure.',
    });
  }

  return findings;
}

// ── Shell scripts ─────────────────────────────────────────────────────────────
const CURL_PIPE_RE = /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|node)\b/i;
const BASE64_PIPE_RE = /base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sh|bash|zsh|node)\b/i;
const PS_DOWNLOAD_RE = /Invoke-Expression|\bIEX\b|DownloadString|FromBase64String/i;
const CERTUTIL_RE = /certutil\s+[^\n]*-urlcache/i;

/** Static malware scan of one shell / PowerShell / batch script. */
export function scanScriptFile(rel: string, content: string): ThreatFinding[] {
  const findings: ThreatFinding[] = [];
  const add = (id: string, title: string, severity: ThreatSeverity, re: RegExp, why: string): void => {
    const idx = indicesOf(re, content);
    if (idx.length > 0) {
      findings.push({ id, title, severity, file: rel, line: lineAt(content, idx[0]), evidence: lineText(content, idx[0]), why });
    }
  };
  add('curl-pipe-shell', 'Remote script piped to a shell', 'critical', CURL_PIPE_RE, 'Downloads a script from the network and runs it immediately. You cannot see what runs.');
  add('base64-pipe-shell', 'Decoded blob piped to a shell', 'critical', BASE64_PIPE_RE, 'Decodes a hidden blob and runs it as a shell script.');
  add('powershell-download-exec', 'PowerShell download-and-execute', 'high', PS_DOWNLOAD_RE, 'Fetches or decodes code and executes it in PowerShell. A common Windows delivery method.');
  add('certutil-download', 'certutil used to download', 'high', CERTUTIL_RE, 'Abuses certutil to pull a remote file. Rarely legitimate in project scripts.');
  return findings;
}

// ── package.json lifecycle scripts ────────────────────────────────────────────
const INSTALL_HOOK_DANGER_RE =
  /\b(?:curl|wget)\b|node\s+(?:-e|--eval)\b|\beval\b|\bbase64\b|certutil|powershell|Invoke-Expression|\bIEX\b|\|\s*(?:sh|bash|zsh)\b/i;

/**
 * Inspect a package.json `scripts` object for install-time hooks. Any preinstall,
 * install, postinstall, or prepare script runs automatically on `npm install`,
 * which is the auto-execution vector. A hook that also fetches or evaluates remote
 * code is critical. A plain build-style hook is a low-severity note, because it
 * still means "this project runs code the moment you install it".
 */
export function scanPackageScripts(scripts: Record<string, string> | undefined): ThreatFinding[] {
  if (!scripts) return [];
  const findings: ThreatFinding[] = [];
  for (const key of INSTALL_HOOK_KEYS) {
    const cmd = scripts[key];
    if (typeof cmd !== 'string' || cmd.trim() === '') continue;
    if (INSTALL_HOOK_DANGER_RE.test(cmd)) {
      findings.push({
        id: 'install-hook-rce',
        title: `Install hook fetches or executes code (${key})`,
        severity: 'critical',
        file: 'package.json',
        evidence: redact(`"${key}": "${cmd}"`),
        why: `The "${key}" script runs automatically on npm install and fetches or evaluates external code. This is the clone-this-repo RCE vector. Do not install this package until you have read this line.`,
      });
    } else {
      findings.push({
        id: 'install-hook',
        title: `Runs code on install (${key})`,
        severity: 'low',
        file: 'package.json',
        evidence: redact(`"${key}": "${cmd}"`),
        why: `The "${key}" script runs automatically on npm install. Read it before you install this project.`,
      });
    }
  }
  return findings;
}

// ── Summary ───────────────────────────────────────────────────────────────────
const SEV_RANK: Record<ThreatSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Fold findings into a verdict. `dangerous` on any critical or high (the run gate
 * trips on this). `suspicious` on a medium. Low findings are informational notes,
 * for example a benign install hook, and do not by themselves change a clean
 * verdict, so the tripwire does not cry wolf on ordinary projects.
 */
export function summarizeThreats(findings: ThreatFinding[], filesScanned: number): ThreatScan {
  const sorted = [...findings].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  let verdict: ThreatVerdict = 'clean';
  if (sorted.some((f) => f.severity === 'critical' || f.severity === 'high')) verdict = 'dangerous';
  else if (sorted.some((f) => f.severity === 'medium')) verdict = 'suspicious';
  return { verdict, findings: sorted, filesScanned };
}

/** True when any finding is an install-time hook, benign or not. Drives the "do not npm install" note. */
export function hasInstallHook(scan: ThreatScan): boolean {
  return scan.findings.some((f) => f.id === 'install-hook' || f.id === 'install-hook-rce');
}
