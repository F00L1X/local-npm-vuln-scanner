# local-npm-vuln-scanner

Scan your workspace for **206 known malicious npm packages** from **16 supply chain attack campaigns** (Oct 2025 - Apr 2026).

Zero dependencies. Pure Node.js. Works on Windows, macOS, and Linux.

## What it detects

| Campaign | Packages | Period | Threat |
|---|---|---|---|
| Strapi Plugin Campaign | 36 | Apr 2026 | Redis/PostgreSQL exploitation via postinstall |
| Axios Supply Chain (Sapphire Sleet) | 4 | Mar 2026 | North Korea RAT via compromised maintainer |
| Ghost Campaign | 13 | Feb-Mar 2026 | Crypto wallet stealers |
| Crypto/CI Secret Harvesters | 19 | Feb 2026 | AI tool typosquats stealing CI secrets |
| Lazarus XPACK Campaign | 34 | Feb 2026 | North Korea credential theft |
| dYdX & Phantom Packages | 7 | Feb 2026 | Hijacked packages delivering wallet stealers |
| Solana/Ethereum Key Stealers | 5 | Feb 2026 | Private key exfiltration via Telegram |
| Flashbots SDK Impersonators | 4 | Feb 2026 | Ethereum wallet credential theft |
| StegaBin Campaign | 26 | Jan 2026 | Pastebin steganography payload delivery |
| NodeCordRAT | 3 | Jan 2026 | Bitcoin-themed RAT delivery |
| Remote Codebase Wiper | 1 | Jan 2026 | Remote-triggered file destruction |
| Phishing Infrastructure | 27 | Dec 2025 | Credential-harvesting phishing pages |
| Lazarus Contagious Interview | 6 | Nov 2025 | North Korea developer targeting |
| MUT-4831 Vidar Infostealer | 4 | Oct-Nov 2025 | Vidar malware via fake Telegram/Cursor packages |
| Credential Stealer Typosquats | 10 | Oct 2025 | Impersonating TypeScript, Discord.js, Ethers, etc. |
| ESLint/Prettier Hijack (CVE-2025-54313) | 7 | Jul 2025 | Phished maintainer, node-gyp.dll malware |

## Quick Start

### One-liner: Download and run (no clone, no install)

**PowerShell (Windows):**

```powershell
# Download and scan current directory
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/F00L1X/local-npm-vuln-scanner/main/scan-malicious-packages.js" -OutFile "scan-malicious-packages.js"; node scan-malicious-packages.js .

# Download and scan a specific workspace
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/F00L1X/local-npm-vuln-scanner/main/scan-malicious-packages.js" -OutFile "scan-malicious-packages.js"; node scan-malicious-packages.js C:\Projects

# Download and scan with JSON output
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/F00L1X/local-npm-vuln-scanner/main/scan-malicious-packages.js" -OutFile "scan-malicious-packages.js"; node scan-malicious-packages.js . --json
```

**curl (macOS / Linux / Git Bash):**

```bash
# Download and scan current directory
curl -sO https://raw.githubusercontent.com/F00L1X/local-npm-vuln-scanner/main/scan-malicious-packages.js && node scan-malicious-packages.js .

# Download and scan a specific workspace
curl -sO https://raw.githubusercontent.com/F00L1X/local-npm-vuln-scanner/main/scan-malicious-packages.js && node scan-malicious-packages.js ~/Projects

# Download and scan with JSON output
curl -sO https://raw.githubusercontent.com/F00L1X/local-npm-vuln-scanner/main/scan-malicious-packages.js && node scan-malicious-packages.js . --json
```

**wget:**

```bash
wget -q https://raw.githubusercontent.com/F00L1X/local-npm-vuln-scanner/main/scan-malicious-packages.js && node scan-malicious-packages.js .
```

> **Tip:** After downloading, you can reuse the script without downloading again. Just run `node scan-malicious-packages.js` from wherever you saved it.

### Run directly with npx (no install needed)

```bash
# Scan the current directory
npx local-npm-vuln-scanner

# Scan a specific workspace
npx local-npm-vuln-scanner C:\Projects

# Scan with JSON output (for CI/CD)
npx local-npm-vuln-scanner --json
```

### Run with Node.js (clone first)

```bash
git clone https://github.com/F00L1X/local-npm-vuln-scanner.git
cd local-npm-vuln-scanner

# Scan current directory
node scan-malicious-packages.js

# Scan a specific directory
node scan-malicious-packages.js /path/to/workspace
```

### Install globally

```bash
npm install -g local-npm-vuln-scanner

# Then use anywhere
local-npm-vuln-scanner C:\Projects
```

## Parameters

| Parameter | Description | Default |
|---|---|---|
| `[directory]` | Directory to scan (positional argument) | Current working directory |
| `--depth N` | Maximum recursion depth for finding `package.json` files | `5` |
| `--history-months N` | How many months of git history to check | `6` |
| `--no-history` | Skip git history scanning entirely | _(history enabled)_ |
| `--json` | Output results as JSON (for CI/CD pipelines) | _(human-readable)_ |
| `--quiet`, `-q` | Only show findings, suppress progress output | _(verbose)_ |
| `--help`, `-h` | Show help message | |

## What it scans

### Current files
- All `package.json` files found recursively (up to `--depth`)
- Checks: `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundledDependencies`
- Also checks `package-lock.json` for transitive/resolved dependencies (v1, v2, and v3 lockfile formats)
- Skips: `node_modules`, `.git`, `dist`, `build`, `.next`, `.nuxt`, `.cache`, `vendor`, and more

### Git history
- For each `package.json` inside a git repository, checks all commits from the last N months
- Detects malicious packages that were present in the past, even if already removed
- Safely skips files that aren't in a git repo (no errors)
- Use `--no-history` to skip this step for faster scans

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No malicious packages found |
| `1` | Malicious package(s) detected (current or history) |

This makes it easy to integrate into CI/CD pipelines:

```bash
# Fail the build if malicious packages are found
npx local-npm-vuln-scanner --json --no-history || exit 1
```

## Version-specific detection

Most packages are flagged on **any version** (entirely malicious packages that should never be installed). Some legitimate packages had specific versions compromised:

| Package | Malicious Versions | Safe Versions |
|---|---|---|
| `axios` | `1.14.1`, `0.30.4` | All others |
| `eslint-config-prettier` | `8.10.1`, `9.1.1`, `10.1.6`, `10.1.7` | All others |
| `eslint-plugin-prettier` | `4.2.2`, `4.2.3` | All others |
| `synckit` | `0.11.9` | All others |
| `@pkgr/core` | `0.2.8` | All others |
| `napi-postinstall` | `0.3.1` | All others |
| `got-fetch` | `5.1.11`, `5.1.12` | All others |
| `is` | `3.3.1`, `5.0.0` | All others |

## Example output

### Human-readable (default)

```
Malicious NPM Package Scanner
==============================
Scan directory:  C:\Projects
Max depth:       5
Packages in DB:  206
Git history:     last 6 months
Campaigns:       16 campaigns (Oct 2025 - Apr 2026)

Scanning current files...

Found 12 package.json file(s)

  Checking my-app\package.json... !! 1 FINDING(S)
  Checking my-api\package.json... OK

  !! MALICIOUS PACKAGES DETECTED (CURRENT): 1 finding(s) !!

================================================================================

  SEVERITY:  CRITICAL
  Package:   strapi-plugin-cron@^1.0.0
  Location:  C:\Projects\my-app\package.json
  Field:     dependencies
  Campaign:  Strapi Plugin Campaign (Apr 2026)
  Details:   ALL versions of this package are malicious
  Reference: https://thehackernews.com/2026/04/36-malicious-npm-packages-exploited.html
================================================================================
```

### JSON output (`--json`)

```json
{
  "scanDate": "2026-04-06T12:00:00.000Z",
  "scanDirectory": "C:\\Projects",
  "maxDepth": 5,
  "historyMonths": 6,
  "packageJsonsScanned": 12,
  "currentFindings": 1,
  "historyFindings": 0,
  "totalFindings": 1,
  "findings": [ ... ],
  "history": []
}
```

## If you find something

1. **Remove** the malicious package from your `package.json`
2. **Delete** `node_modules/` and `package-lock.json`
3. **Run** `npm install` to get clean dependencies
4. **Rotate** all credentials, tokens, and API keys in the affected project
5. **Audit** CI/CD pipelines and build servers that ran during the exposure period
6. **Report** the incident to your security team

## Contributing

Contributions are welcome! This scanner is most useful when its malicious package database stays current.

### Adding new malicious packages

1. Add entries to the `MALICIOUS_PACKAGES` array in `scan-malicious-packages.js`
2. Use `versions: null` for entirely malicious packages (all versions bad)
3. Use `versions: ["x.y.z"]` for compromised versions of legitimate packages
4. Include: `name`, `versions`, `severity` (`CRITICAL` or `HIGH`), `campaign`, and `reference` (URL to source)
5. Group by campaign with a comment header including the date

Example entry:

```js
// ── Campaign Name (Month Year) ──
// Brief description
...[
  "malicious-package-1",
  "malicious-package-2",
].map((name) => ({
  name,
  versions: null,
  severity: "CRITICAL",
  campaign: "Campaign Name (Mon YYYY)",
  reference: "https://source-url.example.com",
})),
```

### Other contributions

- Improve detection logic (e.g., yarn.lock / pnpm-lock.yaml support)
- Add new output formats
- Performance improvements for large workspaces
- Bug fixes and documentation improvements

Please open a PR or issue. All contributions are appreciated.

## Sources

- [36 Malicious npm Packages Exploited Redis, PostgreSQL](https://thehackernews.com/2026/04/36-malicious-npm-packages-exploited.html)
- [Axios npm Package Compromised - Socket](https://socket.dev/blog/axios-npm-package-compromised)
- [CVE-2025-54313 - ESLint/Prettier Hijack](https://github.com/advisories/GHSA-f29h-pxvx-f335)
- [Ghost Campaign Uses 7 npm Packages](https://thehackernews.com/2026/03/ghost-campaign-uses-7-npm-packages-to.html)
- [Malicious npm Packages Harvest Crypto Keys](https://thehackernews.com/2026/02/malicious-npm-packages-harvest-crypto.html)
- [Lazarus Campaign Plants Malicious Packages](https://thehackernews.com/2026/02/lazarus-campaign-plants-malicious.html)
- [Compromised dYdX npm Packages](https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html)
- [27 Malicious npm Packages Used as Phishing Infrastructure](https://thehackernews.com/2025/12/27-malicious-npm-packages-used-as.html)
- [10 npm Packages Caught Stealing Developer Credentials](https://thehackernews.com/2025/10/10-npm-packages-caught-stealing.html)
- [StegaBin: 26 Malicious npm Packages](https://socket.dev/blog/stegabin-26-malicious-npm-packages-use-pastebin-steganography)
- [Lazarus Strikes npm Again](https://socket.dev/blog/lazarus-strikes-npm-again-with-a-new-wave-of-malicious-packages)
- [5 Malicious npm Packages Typosquat Solana/Ethereum](https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys)
- [Flashbots SDK Impersonators](https://socket.dev/blog/malicious-npm-packages-impersonate-flashbots-sdks-targeting-ethereum-wallet-credentials)
- [npm Package Wipes Codebases](https://socket.dev/blog/npm-package-wipes-codebases-with-remote-trigger)
- [MUT-4831 Vidar Infostealer - Datadog](https://securitylabs.datadoghq.com/articles/mut-4831-trojanized-npm-packages-vidar/)
- [NodeCordRAT - Zscaler](https://www.zscaler.com/blogs/security-research/malicious-npm-packages-deliver-nodecordrat)

## License

MIT
