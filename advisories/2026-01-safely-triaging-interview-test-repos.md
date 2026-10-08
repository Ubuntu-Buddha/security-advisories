# Safely Triaging "Interview Test" Repos: A Field Guide to Developer-Targeted Malware

**Author:** Trygve Bundgaard — independent security researcher (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Compiled:** 2026 (from a series of cases analyzed January 2026)
**Type:** Defensive methodology / threat-triage playbook

> A companion to the specific-malware advisories in this repo. This is the
> how-to for catching these before they run, built from real cases.

## Why this exists

Developers — especially web3/crypto developers — are being targeted through fake
job interviews on freelancing and hiring platforms. The "technical test" is the
delivery vehicle: you're asked to clone a repo, open it, run it, and "send
screenshots." The code (or the page) compromises your machine the moment you
cooperate. I analyzed a string of these; this guide is the repeatable method
that caught every one **before any malicious code ran**.

## The delivery vectors seen in the wild

Four confirmed mechanisms (each has its own advisory in this repo), plus others
worth searching for:

| Vector | Trigger | Advisory |
|--------|---------|----------|
| Malicious code in an app startup file → `Function.constructor` RCE | `npm run dev` / server start | [W3GLFun](2026-01-27-contagious-interview-w3glfun-rce.md) |
| `.vscode/tasks.json` with `runOn: folderOpen` → `curl \| sh` | opening the folder in VS Code/Cursor | [IDE auto-run](2026-01-30-ide-autorun-rce-vscode-tasks.md) |
| Runtime `Function.constructor` RCE with the C2 URL hidden in an env var | module load / hitting a route | [env-var variant](2026-01-29-env-var-runtime-rce-optu.md) |
| Fake "careers" page → fake update `.exe` | downloading and running the file | [GAPI update](2026-fake-careers-page-gapi-update-exe.md) |

Also search for (seen across related campaigns): GitHub Actions secret exfil
(`GITHUB_TOKEN` in workflows), Telegram exfiltration (`api.telegram.org`),
Shai-Hulud-style npm worms (`TruffleHog`, `setup_bun.js`), Cursor/`.cursor`
workspace injection, and clipboard-hijack crypto-address swaps.

## Red flags — before you open any code

From the cases that never needed a payload to be obvious (e.g., two Bitbucket
repos I declined on these signals alone):

- **Job/repo mismatch.** Posting says "WordPress developer," repo is a Next.js
  casino; posting says "Web3 fintech," repo is a personal finance assistant with
  no blockchain code at all. Tech-stack and project mismatches are a top tell.
- **Pressure to execute.** "Clone and check it on your side ASAP," "run it and
  tell me if it runs," "leave the screenshots as a result." Legitimate interviews
  don't rush you to run unknown code.
- **Throwaway infrastructure.** Brand-new account/org (days old), a single
  repository, a single "initial commit" (or two "initial commit"s = rewritten
  history), unrelated repo tags (a "shopify" tag on a blockchain repo).
- **Evasive counterpart.** Dodges technical questions, won't discuss the code
  before you run it.
- **Author that doesn't add up.** Commits attributed to a well-known developer
  but **unsigned** (no GPG verification) and from someone not actually in the org
  — git author spoofing. The displayed name is not proof of authorship.

Any one of these justifies slowing down; two or more justifies declining.

## Safe inspection protocol — online first, never clone first

The core principle: **read the files without giving them a chance to run.** No
clone, no `npm install`, no opening the folder in an IDE.

1. **Fetch raw file contents, don't clone.**
   - Public GitHub: `https://raw.githubusercontent.com/OWNER/REPO/BRANCH/path`
   - Private repo: view in the browser while logged in; copy the file text. Don't "Open in Desktop."
2. **Read the high-risk files first:**
   - `.vscode/tasks.json` → look for `runOn`/`folderOpen`, `curl`/`wget`, `| sh`/`| cmd`, `reveal: never`. **Scroll right** — payloads are hidden past whitespace padding.
   - `package.json` → `preinstall`/`postinstall` and any script invoking `curl`/`wget`.
   - lockfile → non-registry `resolved` URLs, paste-service/shortener domains.
   - `Dockerfile` → `RUN curl … | sh`.
   - controllers/route handlers and "utility"/"error handler" files → `Function.constructor`, `new Function(...)`, `atob(process.env.*)`, `axios.get(... )` feeding executed code.
3. **Grep for the execution primitives** (works regardless of obfuscation):
   ```bash
   grep -rn "Function.constructor\|new Function(" .
   grep -rn "atob(process.env\|Buffer.from(.*base64" .
   grep -rn "folderOpen" --include=tasks.json .
   grep -rn "curl .*| *sh\|wget .*| *sh\|| *cmd" .
   ```
4. **Only if you must run it, use a disposable VM/container** with no wallets,
   keys, or credentials present and networking off. Treat anything it fetches as
   hostile.

## Hardening that neutralizes whole classes

- **Keep VS Code Workspace Trust on** (`security.workspace.trust.enabled`) — Restricted Mode stops `tasks.json` auto-run.
- **Verify commit signatures;** don't trust a displayed author name.
- **Keep your daily driver clean** — do untrusted analysis on a machine (or VM) that holds no secrets.
- **Never run an `.exe` or install prompt** that appears inside an application/interview flow, even on a trusted-looking domain.

## Reporting works

These are worth reporting: in one case, after I reported the malicious repo to
**GitHub Trust & Safety**, they confirmed a Terms-of-Service violation and
removed it. Report repos to GitHub/Bitbucket, pages to Google/Vercel abuse, and
the job to the hiring platform — it protects the next developer.

---

*Published for the protection of the developer community. Individuals' names
withheld; indicators defanged in the linked advisories. — Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
