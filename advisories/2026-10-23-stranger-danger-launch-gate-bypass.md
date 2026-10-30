# Launch Gate Bypasses in the StrangerDanger Claude Code Plugin v0.1.0 (GHSA-w42w-fc6x-88wr)

**Author:** Trygve Bundgaard — independent security researcher and the plugin's maintainer (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Published:** 2026-10-23 (UTC), as GitHub Security Advisory [GHSA-w42w-fc6x-88wr](https://github.com/Ubuntu-Buddha/claude-code-stranger-danger/security/advisories/GHSA-w42w-fc6x-88wr)
**Status:** Patched in [v0.1.1](https://github.com/Ubuntu-Buddha/claude-code-stranger-danger/releases/tag/v0.1.1) (see the Monitor caveat under "The fix in v0.1.1"). A CVE was requested; none assigned as of 2026-10-30.
**Severity:** Moderate (GitHub's label; CVSS 3.1 rating Medium) — `CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`, score 6.3
**Type:** Vulnerability in my own security tool, found and disclosed by its maintainer

## Summary

[StrangerDanger](https://github.com/Ubuntu-Buddha/claude-code-stranger-danger)
is a Claude Code plugin I maintain. Its launch gate is a PreToolUse hook that
reads the shell command an agent is about to run and refuses known-dangerous
forms. In v0.1.0 the gate's checks could be bypassed: the ssh option checks
through command text the gate parsed differently from bash, and every check
through the Monitor tool or through shell forms that hid the command.

The gaps were found during the maintainer's own review. I addressed them in
v0.1.1, with the caveats below, and published the advisory on the plugin's repository.

| | |
|---|---|
| Package | Claude Code plugin `stranger-danger` (`Ubuntu-Buddha/claude-code-stranger-danger`) |
| Affected | 0.1.0 |
| Patched | 0.1.1 |
| Advisory | GHSA-w42w-fc6x-88wr |
| CVE | Requested; none assigned as of 2026-10-30 |
| Credit | Found during the maintainer's own review |

## The three gaps

1. **Text beside ssh, scp or sftp that the gate read differently from bash.**
   Users who list `ssh`, `scp` or `sftp` in `sandbox.excludedCommands`, so
   agents can reach their servers with their own keys, rely on the gate to keep
   those calls to plain remote access: no option that runs a local command, and
   no second command alongside. Four classes of text got past it:
   - a trailing line that doesn't parse;
   - an arithmetic expansion that holds a command substitution;
   - a heredoc marker hidden inside another construct, so the parser took the
     following lines as heredoc text while the shell runs them as commands;
   - words that bash expands before ssh sees them (brace expansion, parameter
     defaults and similar expansions, or an unquoted glob that can pick up a
     planted file), because the gate checked the words as written.

   In each case the gate saw a harmless ssh call and passed text that the
   shell would run differently: a second command, or an ssh option that runs a
   local program.
2. **The Monitor tool.** Claude Code's Monitor tool runs a shell command; the
   GHSA notes that Claude Code's docs say it uses the same permission rules as
   Bash and that the sandbox covers it as it covers Bash. The plugin registered
   the launch gate for the `Bash` tool only, so a command run through Monitor
   got none of the gate's checks: launchers, downloads piped into an
   interpreter, privilege escalation, agents started with permissions off, and
   the ssh checks.
3. **Three shell forms that hid the command, in Bash and Monitor alike.**
   - A redirect that names its file descriptor with a variable, placed before
     the command, was read by the gate as the command word.
   - A brace expansion let bash build a command, a subcommand or a `-c`
     payload that the gate never saw.
   - A word in front of the command that bash drops when it comes out empty
     (an unset variable, an empty substitution, an empty brace expansion) was
     read as the command word.

   Each way, the gate's checks on that command were skipped, the ssh checks
   included.

## Impact

An agent that has been steered by a web page, document or other untrusted
text could run a command the gate is meant to refuse.

- **Gap 1** matters only when the user's sandbox exempts ssh, scp or sftp
  **with their arguments**. There, the command could run outside Claude Code's
  sandbox with the user's rights. How `sandbox.excludedCommands` is written
  decides it. The GHSA cites Claude Code's settings reference: an entry without
  a wildcard matches only that exact command, so a bare `"ssh"` should exempt
  only `ssh` with no arguments, while a pattern such as `"ssh *"` (or any other
  wildcard form) exempts ssh with any arguments. That matching wasn't tested on
  a live install, so if you list ssh, scp or sftp in any form, treat yourself
  as affected until you upgrade.
- **Gaps 2 and 3** leave Claude Code's own sandbox and permission rules in
  place. What was lost is the gate's checks on top of them, including its ssh
  checks for users who exempt ssh. For a user with an exemption such as
  `"ssh *"`, gaps 2 and 3 can have the same impact as gap 1 on an ssh, scp or
  sftp call: through Monitor the ssh checks didn't run at all, and, as the GHSA
  notes, Claude Code's docs don't say how `excludedCommands` matches a call
  that starts with a redirect or an empty word, or one whose command is built
  by brace expansion. Those docs also say the excluded-commands list isn't a
  security boundary, so don't rely on how it matches. Without Claude Code's
  sandbox, only its permission rules and prompts stood behind the gate.
- The plugin's reader gate (web and file reads) and its reader agents aren't
  affected.

**Why Moderate.** The bypass needs an agent that is already being steered by
injected text (UI:R: the user runs an agent that reads it), and, for the
larger part of the impact, a sandbox exemption for ssh, scp or sftp with their
arguments (AC:H). Where that exemption exists, the result is a local command
running outside the sandbox with the user's rights (C:H, I:H). Scope is scored
Unchanged because the escape comes from the user's own exemption, not from
breaking the sandbox; scored as Changed, the same vector would be about 7.4.
The launch gate is documented as a tripwire, not a security boundary, but its
ssh checks are a stated protection for users who exempt ssh, so a bypass of
those is in scope.

## The fix in v0.1.1

- Text that names ssh, scp or sftp anywhere, including names split by quotes,
  backslashes or empty ANSI-C quotes or spelled with escapes, is refused when
  it has a second line, a carriage return, a heredoc or here-string, an
  arithmetic expansion, or doesn't parse.
- An ssh-family word that bash would expand (an unquoted `$`, brace or glob
  character, or a `$` inside double quotes) is refused.
- The launch gate is registered for `Bash|Monitor` and gives Monitor commands
  the same checks. It refuses a Monitor input field it doesn't know, Monitor's
  WebSocket watch, and, as a tripwire, a Monitor command that names a
  downloader or network client or builds its command name at run time.
- A redirect that names its file descriptor with a variable is read as a
  redirect, as bash reads it. Words are brace-expanded as bash would before
  the gate checks them. When words up to the command word are built at run
  time, the command is also checked as bash would run it with them empty,
  within limits. That last check is a tripwire: a variable that holds a
  command name is still a known gap.
- Hardened in the same release, outside this advisory's impact: more ssh
  options are refused, and a call that asks for per-call network hosts is
  handed to Claude Code's permission prompt naming each host. That prompt was
  observed only on Claude Code 2.1.309, for Bash with the sandbox on in auto
  mode (`docs/VERIFY.md` row M2), where it appeared each time even with an
  allow rule matching every command. Other versions and modes, Monitor calls,
  and another hook or SDK callback that might approve the prompt unseen
  weren't tested. If you use any of those, or haven't run row M2 yourself, set
  `launch_gate.ask_for_domains` to `false` to have such calls refused.

**Monitor caveat.** Claude Code's hook docs don't list Monitor as a hook
matcher, so v0.1.1's settings template denies the Monitor tool. After
upgrading, keep `Monitor` in `permissions.deny` until the plugin's
verification row M1 passes on your Claude Code version. M1 checks only a
main-session call in default mode, so if subagents may use Monitor or you work
in another mode, keep the deny.

## Workarounds

For users who can't upgrade yet:

- Add `"Monitor"` to `permissions.deny` in `~/.claude/settings.json`. This is
  meant to cover gap 2.
- Don't list `ssh`, `scp` or `sftp` in `sandbox.excludedCommands`. This is the
  only settings workaround that also covers gaps 1 and 3 on those calls. An
  `ask` rule for them covers gap 1 if you read each prompt in full before
  approving.
- Keep `sandbox.allowUnsandboxedCommands` set to `false`.
- Beyond not exempting ssh, scp and sftp, gap 3 has no settings workaround.
  Keep the sandbox on with a tight `sandbox.network.allowedDomains`: that is
  the real control the gate sits on top of.

## Timeline

- **2026-10-23 (UTC):** GHSA-w42w-fc6x-88wr published on the plugin's
  repository, with v0.1.1 as the patched version.
- **As of 2026-10-30:** a CVE has been requested; none assigned.

## References

- [GHSA-w42w-fc6x-88wr](https://github.com/Ubuntu-Buddha/claude-code-stranger-danger/security/advisories/GHSA-w42w-fc6x-88wr)
- [v0.1.1 release](https://github.com/Ubuntu-Buddha/claude-code-stranger-danger/releases/tag/v0.1.1)
- In the plugin's repository: `CHANGELOG.md` `[0.1.1]`; `docs/VERIFY.md` rows
  M1 and M2; `docs/verify/RESULTS-2026-10-22-cc2.1.301-2.1.309.md`

---

*Disclosed by the maintainer for the protection of the plugin's users. —
Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
