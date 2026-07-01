# Obra CTO

A local-first MCP server that scores your codebase's Build Readiness. You install
it in your own Claude. Your Claude reads your code on your machine and runs your
tests there. Nothing is uploaded.

This is the free preview of Obra's role lineup, and it stays free and local. The CTO
reads your code and tells you what an investor's technical diligence would find: real
security holes, weak design decisions, and the gaps that stop a serious review. The
rest of the team (the Obra CFO for funding-ready materials, and more) lives in the
Build with Obra community.

## Why local-first

A tool that reads your code should not ship your code somewhere. This server makes
no network calls. It returns counts, presence flags, a redacted secrets scan, and a
score. Your source stays where it is. You can read every line of this server before
you run it, which is the point of keeping it open.

## What you get

The Obra CTO Score, out of 100, calibrated to your stage (prototype, MVP, or
growth), across six dimensions:

| Dimension | Weight |
|---|---|
| Security | 25 |
| Product reality (what is actually built) | 20 |
| Robustness | 15 |
| Architecture | 15 |
| Maintainability | 15 |
| Deploy readiness | 10 |

Every finding carries an evidence grade: A verified, B multiple sources, C partial
or inferred, D claim only, E speculation. The score is built from grade A and C
evidence, what is true in your code, not what a deck says. When the CTO runs your
tests and they pass, reliability becomes grade A. A deck-scorer can never earn that.

## What a run looks like

Point it at a real project and you get a scored report with a ranked risk register.
Here is a run on a scrappy Supabase app (anonymized):

```
# Obra CTO Score: financeapp
## 46 / 100 · Not yet ready
Assessed as: mobile (react-native, expo)  |  Backend: supabase

| Dimension        | Score | Evidence |
|------------------|-------|----------|
| Security         | 6/25  | A |
| Product reality  | 20/20 | A |
| Robustness       | 3/15  | A |
| Architecture     | 9/15  | A |
| Maintainability  | 6/15  | A |
| Deploy readiness | 2/10  | C |

## Top Risks
- [critical] RLS policies defined but never enabled; data may be open to any authenticated user
    Fix: enable row level security on every table, then verify a second user cannot read your rows.
- [high] Access control gap: a privileged action checks only that the user is logged in, not that they own the resource
- [medium] No tests found
```

On a well-built app it scores high and credits the good engineering. It is calibrated,
not a fear machine.

## Tools

- `scan_project` reads the project and returns mechanical signals.
- `check_dependencies` checks your locked dependencies against the OSV vulnerability
  database. Only package names and versions leave your machine, never your code.
- `run_tests` runs your test suite (this executes code, so your Claude asks first)
  and parses the pass and fail counts.
- `prepare_code_review` selects your highest-signal files (schema and policy files,
  entry points, security-relevant code) and hands them to your Claude with a checklist
  tuned to your stack, including a Backend-as-a-Service lens (Supabase, Firebase) and a
  design red-team that critiques the architecture, not just the code.
- `score_build_readiness` produces the Obra CTO Score with a Top Risks register.

A normal run is: scan, check dependencies, run tests, prepare the code review, then score.

## Install

Add it to your Claude MCP config (Claude Desktop or Claude Code):

```json
{
  "mcpServers": {
    "obra-cto": {
      "command": "npx",
      "args": ["-y", "obra-cto"]
    }
  }
}
```

Then ask your Claude: "Score this project's build readiness with Obra CTO."

Prefer to run from source? Clone the repo, run `npm install && npm run build`, and
point the config at `node /absolute/path/to/obra-cto/dist/index.js`.

## What this is not

Not a linter, not a security scanner, not a replacement for your own Claude reading
the code. It is technical-diligence readiness inside funding readiness: the question
an investor's CTO would ask, answered from your real code.

## What's next

The Obra CTO is the free preview. To go further:

- **The Method:** the full playbook for shipping production software with AI, the
  disciplines that make code score like the example above, each lesson with a paste-in
  prompt or tool you can use today.
- **The rest of the team:** the Obra CFO for funding-ready materials, and each new
  role as it ships.
- **Obra itself, in beta:** the AI employee that runs your back office. Members go first.

It all lives in Build with Obra: https://www.skool.com/build-with-obra-5361/about

## License

Apache-2.0.
