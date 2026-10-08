# Fake "Careers" Page Pushing a Malicious "GAPI Update" Executable (Google Sites abuse)

**Author:** Trygve Bundgaard — independent security researcher (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Discovered:** 2026
**Status:** Phishing / malware distribution. Declined; reportable to the freelancing platform and to Google Sites abuse.
**Severity:** High — social-engineers the target into downloading and running an attacker-supplied Windows executable
**Type:** Fake-update malware via trusted-domain (Google Sites) abuse

> Indicators are defanged (`[.]`). Do not visit the page or download anything outside an isolated environment.

## Summary

Not every developer-targeting lure is a code repo. In this case an Upwork job
directed applicants to a **Google Sites "careers" page** that displayed a fake
authentication error and urged the visitor to **download and run a Windows
executable ("GAPI Update (.exe)")** to "restore service." Submitting a Google
Form never requires installing an `.exe` — the download is malware. The attack
leans entirely on the credibility of the `sites.google.com` domain.

## The lure

1. The job posting links to `hxxps://sites[.]google[.]com/view/artes-project-careers/forms`.
2. The page shows a fabricated error — `GAPI_AUTH_FAILED`, *"401 — Authentication credentials expired or invalid"*, *"Download and install the latest Google API Authentication update."*
3. A prominent button offers **"Download GAPI Update (.exe)"**.
4. Social-engineering pressure: framed as a "known issue" with a "recommended solution," creating urgency and false authority.

## Why it's convincing

`sites.google.com` is Google's real domain, and anyone can publish a free page
at `sites.google.com/view/<name>`. So the URL genuinely resolves to Google
infrastructure — only the **content** is attacker-controlled. The padlock, the
Google domain, and official-sounding error codes ("GAPI", "401") are enough to
get a hurried applicant to run the file.

## Indicators of compromise (defanged)

| Indicator | Value |
|-----------|-------|
| Hosting page | `hxxps://sites[.]google[.]com/view/artes-project-careers/forms` |
| Fake error strings | `GAPI_AUTH_FAILED`, `401 - Authentication credentials expired or invalid`, "Google API Authentication update" |
| Payload | a downloadable Windows executable labeled **"GAPI Update (.exe)"** |
| Delivery pattern | legitimate Google-domain page → fake error → fake-update `.exe` |

## Impact

Running the executable is arbitrary native code on a Windows machine — the same
end goal as the repo-based backdoors (credential, wallet-key, and SSH-key theft;
persistence), delivered through a file the victim is tricked into launching.

## Detection / red flags

- A "form" or "careers" page that asks you to **download software** to continue. Google Forms never requires an installed update.
- Error codes and "update" prompts that appear **inside page content** rather than from your browser or OS.
- Any interview/application flow whose next step is "run this `.exe`."

## Safe handling

- **Never download or run executables** from an application or interview flow.
- Treat a trusted domain (`sites.google.com`, `*.vercel.app`, `*.web.app`) as **no guarantee of trusted content** — these are open publishing platforms.
- Report the page to **Google Sites abuse** and the job to the freelancing platform.

## Campaign context

Same objective as the repo-delivered backdoors (compromise a job-seeking
developer) via a different channel — a fake update executable behind a
trusted-looking Google URL. Abuse of Google Forms/Sites for malware and
credential theft is well documented by multiple vendors; this is that pattern
pointed at developer hiring.

---

*Published for the protection of the developer community. Indicators defanged. — Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
