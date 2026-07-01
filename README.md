# Obra CTO

A local-first MCP server that scores your codebase's Build Readiness. You install
it in your own Claude. Your Claude reads your code on your machine and runs your
tests there. Nothing is uploaded.

This is the free preview of Obra's role lineup. The CTO reads your code and tells
you what an investor's technical diligence would find. The paid Obra CFO turns that
verified picture into funding-ready materials and the EU loan, grant, and investor
path.

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

## Tools

- `scan_project` reads the project and returns mechanical signals.
- `run_tests` runs your test suite (this executes code, so your Claude asks first)
  and parses the pass and fail counts.
- `score_build_readiness` produces the Obra CTO Score with a Top Risks register.

A normal run is: scan, then run tests, then score with the test numbers.

## Install

Build it:

```bash
npm install
npm run build
```

Add it to your Claude MCP config (Claude Desktop or Claude Code):

```json
{
  "mcpServers": {
    "obra-cto": {
      "command": "node",
      "args": ["/absolute/path/to/obra-cto/dist/index.js"]
    }
  }
}
```

Then ask your Claude: "Score this project's build readiness with Obra CTO."

## What this is not

Not a linter, not a security scanner, not a replacement for your own Claude reading
the code. It is technical-diligence readiness inside funding readiness: the question
an investor's CTO would ask, answered from your real code.

## License

Apache-2.0.
