# Security Advisories

Threat-analysis and vulnerability-disclosure writeups by **Trygve Bundgaard**
(GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha)).

Defensive security research: malware targeting software developers and
vulnerabilities in my own AI-agent tooling (a Claude Code plugin). I also
work on vulnerability disclosure for web3 / Solana / EVM platforms; no such
writeup is published here yet. All indicators of compromise below are **defanged**
(`hxxp`, `[.]`) so this page is safe to read and copy.

## Advisories

| Date | Title | Type | Status |
|------|-------|------|--------|
| 2026-10-23 | [Launch gate bypasses in the StrangerDanger Claude Code plugin v0.1.0 (GHSA-w42w-fc6x-88wr)](advisories/2026-10-23-stranger-danger-launch-gate-bypass.md) | Vulnerability / security-tool bypass | Found in the maintainer's own review; patched in v0.1.1 (keep Monitor denied; see advisory); GHSA published 2026-10-23; CVE requested, none assigned as of 2026-10-30 |
| 2026-10-15 | [Hex payload hidden in a fake font file, run by a `new Function` loader (coinbucket/dex-mvp)](advisories/2026-10-15-fake-font-hex-loader-dex-mvp.md) | Malware / RCE | Malware identified before execution by remote review; reported to GitLab and Upwork 2026-10-15, outcome pending |
| 2026-01-30 | [IDE auto-execute RCE via malicious `.vscode/tasks.json`](advisories/2026-01-30-ide-autorun-rce-vscode-tasks.md) | Malware / RCE | Malware identified before execution; one of the two repos reported to GitHub; both accounts now 404 |
| 2026-01-29 | [Runtime RCE backdoor hidden in an environment variable (Optu-Consulting)](advisories/2026-01-29-env-var-runtime-rce-optu.md) | Malware / RCE | Malware identified before execution; account and repo now 404 |
| 2026-01-29 | [Fake "careers" page pushing a malicious "GAPI Update" .exe (Google Sites abuse)](advisories/2026-fake-careers-page-gapi-update-exe.md) | Malware / phishing | Malware identified before execution; reportable to platform & Google |
| 2026-01-27 | [RCE backdoor in a fake "Web3 developer" interview test (TechPro-1/W3GLFun)](advisories/2026-01-27-contagious-interview-w3glfun-rce.md) | Malware / RCE | Reported; GitHub Trust & Safety took action against the account; account now 404 |

### Methodology

- [Safely triaging "interview test" repos: a field guide to developer-targeted malware](advisories/2026-01-safely-triaging-interview-test-repos.md) — red-flag taxonomy, safe online-first inspection protocol, and the campaign's delivery-vector catalog.

## Contact

Report malware or vulnerabilities to me via my GitHub profile.

## License

The writeups in this repository are licensed under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE),
© 2026 Trygve Bundgaard. Malicious code, attacker messages, and platform
emails quoted for analysis belong to their authors and are not covered by
this license.
