# Security Advisories

Coordinated-disclosure and threat-analysis writeups by **Trygve Bundgaard**
(GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha)).

Defensive security research: malware targeting software developers, and
vulnerability disclosure on web3 / Solana / EVM platforms. All indicators of
compromise below are **defanged** (`hxxp`, `[.]`) so this page is safe to read
and copy.

## Advisories

| Date | Title | Type | Status |
|------|-------|------|--------|
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
