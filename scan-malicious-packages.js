#!/usr/bin/env node

/**
 * Malicious NPM Package Scanner
 *
 * Scans a directory recursively (up to depth 5) for package.json files
 * and checks all dependencies against known malicious packages.
 *
 * Sources:
 *   - https://thehackernews.com/2026/04/36-malicious-npm-packages-exploited.html
 *   - https://socket.dev/blog/axios-npm-package-compromised
 *   - https://github.com/advisories/GHSA-f29h-pxvx-f335
 *   - https://thehackernews.com/2026/03/ghost-campaign-uses-7-npm-packages-to.html
 *   - https://thehackernews.com/2026/02/malicious-npm-packages-harvest-crypto.html
 *   - https://thehackernews.com/2026/02/lazarus-campaign-plants-malicious.html
 *   - https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html
 *   - https://thehackernews.com/2025/12/27-malicious-npm-packages-used-as.html
 *   - https://thehackernews.com/2025/10/10-npm-packages-caught-stealing.html
 *   - https://socket.dev/blog/stegabin-26-malicious-npm-packages-use-pastebin-steganography
 *   - https://socket.dev/blog/lazarus-strikes-npm-again-with-a-new-wave-of-malicious-packages
 *   - https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys
 *   - https://socket.dev/blog/malicious-npm-packages-impersonate-flashbots-sdks-targeting-ethereum-wallet-credentials
 *   - https://socket.dev/blog/npm-package-wipes-codebases-with-remote-trigger
 *   - https://securitylabs.datadoghq.com/articles/mut-4831-trojanized-npm-packages-vidar/
 *   - https://www.zscaler.com/blogs/security-research/malicious-npm-packages-deliver-nodecordrat
 *
 * Usage:
 *   node scan-malicious-packages.js [directory] [--depth N] [--json] [--quiet]
 *
 * Examples:
 *   node scan-malicious-packages.js                    # scan current directory
 *   node scan-malicious-packages.js C:\Projects        # scan specific directory
 *   node scan-malicious-packages.js --depth 3          # limit recursion depth
 *   node scan-malicious-packages.js --json             # output JSON for CI/CD
 *   node scan-malicious-packages.js --quiet            # only show findings
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

// ─── Malicious Package Registry ──────────────────────────────────────────────
// Each entry: { name, versions (null = ALL versions), severity, campaign, reference }

const MALICIOUS_PACKAGES = [
  // ═══════════════════════════════════════════════════════════════════════════
  // APRIL 2026
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Strapi Plugin Campaign (April 2026) ──
  // 36 fake Strapi plugins with postinstall scripts exploiting Redis & PostgreSQL
  ...[
    "strapi-plugin-cron",
    "strapi-plugin-config",
    "strapi-plugin-server",
    "strapi-plugin-database",
    "strapi-plugin-core",
    "strapi-plugin-hooks",
    "strapi-plugin-monitor",
    "strapi-plugin-events",
    "strapi-plugin-logger",
    "strapi-plugin-health",
    "strapi-plugin-sync",
    "strapi-plugin-seed",
    "strapi-plugin-locale",
    "strapi-plugin-form",
    "strapi-plugin-notify",
    "strapi-plugin-api",
    "strapi-plugin-sitemap-gen",
    "strapi-plugin-nordica-tools",
    "strapi-plugin-nordica-sync",
    "strapi-plugin-nordica-cms",
    "strapi-plugin-nordica-api",
    "strapi-plugin-nordica-recon",
    "strapi-plugin-nordica-stage",
    "strapi-plugin-nordica-vhost",
    "strapi-plugin-nordica-deep",
    "strapi-plugin-nordica-lite",
    "strapi-plugin-nordica",
    "strapi-plugin-finseven",
    "strapi-plugin-hextest",
    "strapi-plugin-cms-tools",
    "strapi-plugin-content-sync",
    "strapi-plugin-debug-tools",
    "strapi-plugin-health-check",
    "strapi-plugin-guardarian-ext",
    "strapi-plugin-advanced-uuid",
    "strapi-plugin-blurhash",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Strapi Plugin Campaign (Apr 2026)",
    reference:
      "https://thehackernews.com/2026/04/36-malicious-npm-packages-exploited.html",
  })),

  // ═══════════════════════════════════════════════════════════════════════════
  // MARCH 2026
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Axios Supply Chain Compromise (March 2026) ──
  // North Korea-nexus (Sapphire Sleet) compromised axios maintainer account
  {
    name: "axios",
    versions: ["1.14.1", "0.30.4"],
    severity: "CRITICAL",
    campaign: "Axios Supply Chain Compromise - Sapphire Sleet (Mar 2026)",
    reference: "https://socket.dev/blog/axios-npm-package-compromised",
  },
  ...[
    "plain-crypto-js",
    "@shadanai/openclaw",
    "@qqbrowser/openclaw-qbot",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Axios Supply Chain Compromise - Sapphire Sleet (Mar 2026)",
    reference: "https://socket.dev/blog/axios-npm-package-compromised",
  })),

  // ── Ghost Campaign (Feb-Mar 2026) ──
  // Crypto wallet stealers and credential theft
  ...[
    "react-performance-suite",
    "react-state-optimizer-core",
    "react-fast-utilsa",
    "ai-fast-auto-trader",
    "pkgnewfefame1",
    "carbon-mac-copy-cloner",
    "coinbase-desktop-sdk",
    "react-query-core-utils",
    "react-state-optimizer",
    "react-fast-utils",
    "darkslash",
    "carbon-mac-copys-cloner",
    "pkgnewfefame",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Ghost Campaign - Crypto Wallet Stealer (Feb-Mar 2026)",
    reference:
      "https://thehackernews.com/2026/03/ghost-campaign-uses-7-npm-packages-to.html",
  })),

  // ═══════════════════════════════════════════════════════════════════════════
  // FEBRUARY 2026
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Crypto/CI Secret Harvesters (Feb 2026) ──
  // Steal crypto keys, CI secrets, API tokens; some target AI coding tools
  ...[
    "claud-code",
    "cloude-code",
    "cloude",
    "crypto-locale",
    "crypto-reader-info",
    "detect-cache",
    "format-defaults",
    "hardhta",
    "locale-loader-pro",
    "naniod",
    "node-native-bridge",
    "opencraw",
    "parse-compat",
    "rimarf",
    "scan-store",
    "secp256",
    "suport-color",
    "veim",
    "yarsg",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Crypto/CI Secret Harvesters (Feb 2026)",
    reference:
      "https://thehackernews.com/2026/02/malicious-npm-packages-harvest-crypto.html",
  })),

  // ── Lazarus XPACK Campaign (Feb 2026) ──
  // North Korea-linked Lazarus Group, credential theft
  ...[
    "graphalgo",
    "graphorithm",
    "graphstruct",
    "graphlibcore",
    "netstruct",
    "graphnetworkx",
    "terminalcolor256",
    "graphkitx",
    "graphchain",
    "graphflux",
    "graphorbit",
    "graphnet",
    "graphhub",
    "terminal-kleur",
    "graphrix",
    "bignumx",
    "bignumberx",
    "bignumex",
    "bigmathex",
    "bigmathlib",
    "bigmathutils",
    "graphlink",
    "bigmathix",
    "graphflowx",
    "duer-js",
    "xpack-per-user",
    "xpack-per-device",
    "xpack-sui",
    "xpack-subscription",
    "xpack-arc-gateway",
    "xpack-video-submission",
    "test-npm-style",
    "xpack-subscription-test",
    "testing-package-xdsfdsfsc",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Lazarus XPACK Campaign (Feb 2026)",
    reference:
      "https://thehackernews.com/2026/02/lazarus-campaign-plants-malicious.html",
  })),

  // ── Compromised dYdX & Phantom Packages (Feb 2026) ──
  // Hijacked legitimate packages delivering wallet stealers and RAT
  ...[
    "@dydxprotocol/v4-client-js",
    "openapi-generator-cli",
    "cucumber-js",
    "depcruise",
    "jsdoc2md",
    "grpc_tools_node_protoc",
    "vue-demi-switch",
  ].map((name) => ({
    name,
    versions: null,
    severity: "HIGH",
    campaign: "dYdX & Phantom Packages Compromise (Feb 2026)",
    reference:
      "https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html",
  })),

  // ── Crypto Key Stealers - Solana/Ethereum (Feb 2026) ──
  // Typosquat Solana/Ethereum libraries, exfiltrate private keys via Telegram
  ...[
    "raydium-bs58",
    "base-x-64",
    "bs58-basic",
    "ethersproject-wallet",
    "base_xd",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Solana/Ethereum Key Stealers (Feb 2026)",
    reference:
      "https://socket.dev/blog/5-malicious-npm-packages-typosquat-solana-and-ethereum-libraries-steal-private-keys",
  })),

  // ── Flashbots SDK Impersonators (Feb 2026) ──
  // Steal Ethereum wallet credentials
  ...[
    "@flashbotts/ethers-provider-bundle",
    "flashbot-sdk-eth",
    "sdk-ethers",
    "gram-utilz",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Flashbots SDK Impersonators (Feb 2026)",
    reference:
      "https://socket.dev/blog/malicious-npm-packages-impersonate-flashbots-sdks-targeting-ethereum-wallet-credentials",
  })),

  // ═══════════════════════════════════════════════════════════════════════════
  // JANUARY 2026
  // ═══════════════════════════════════════════════════════════════════════════

  // ── StegaBin Campaign (Jan 2026) ──
  // 26 typosquats using Pastebin steganography for payload delivery
  ...[
    "formmiderable",
    "bubble-core",
    "mqttoken",
    "windowston",
    "bee-quarl",
    "kafkajs-lint",
    "jslint-config",
    "zoddle",
    "daytonjs",
    "corstoken",
    "jsnwebapptoken",
    "iosysredis",
    "sequelization",
    "undicy-lint",
    "expressjs-lint",
    "loadash-lint",
    "promanage",
    "vitetest-lint",
    "prism-lint",
    "fastify-lint",
    "typoriem",
    "argonist",
    "uuindex",
    "bcryptance",
    "hapi-lint",
    "ether-lint",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "StegaBin Campaign (Jan 2026)",
    reference:
      "https://socket.dev/blog/stegabin-26-malicious-npm-packages-use-pastebin-steganography",
  })),

  // ── NodeCordRAT (Jan 2026) ──
  // Deliver remote access trojan via Bitcoin-themed packages
  ...[
    "bitcoin-main-lib",
    "bitcoin-lib-js",
    "bip40",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "NodeCordRAT - Bitcoin Package Typosquats (Jan 2026)",
    reference:
      "https://www.zscaler.com/blogs/security-research/malicious-npm-packages-deliver-nodecordrat",
  })),

  // ── Codebase Wiper (Jan 2026) ──
  // Remote-triggered codebase destruction
  {
    name: "xlsx-to-json-lh",
    versions: null,
    severity: "CRITICAL",
    campaign: "Remote Codebase Wiper (Jan 2026)",
    reference:
      "https://socket.dev/blog/npm-package-wipes-codebases-with-remote-trigger",
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DECEMBER 2025
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Phishing Infrastructure Packages (Dec 2025) ──
  // 27 packages hosting credential-harvesting phishing pages
  ...[
    "adril7123",
    "ardril712",
    "arrdril712",
    "androidvoues",
    "assetslush",
    "axerification",
    "erification",
    "erificatsion",
    "errification",
    "eruification",
    "hgfiuythdjfhgff",
    "homiersla",
    "houimlogs22",
    "iuythdjfghgff",
    "iuythdjfhgff",
    "iuythdjfhgffdf",
    "iuythdjfhgffs",
    "iuythdjfhgffyg",
    "jwoiesk11",
    "modules9382",
    "onedrive-verification",
    "sarrdril712",
    "scriptstierium11",
    "secure-docs-app",
    "sync365",
    "ttetrification",
    "vampuleerl",
  ].map((name) => ({
    name,
    versions: null,
    severity: "HIGH",
    campaign: "Phishing Infrastructure Packages (Dec 2025)",
    reference:
      "https://thehackernews.com/2025/12/27-malicious-npm-packages-used-as.html",
  })),

  // ═══════════════════════════════════════════════════════════════════════════
  // NOVEMBER 2025
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Lazarus Contagious Interview Campaign (Nov 2025) ──
  // North Korean threat actor targeting developers
  ...[
    "is-buffer-validator",
    "yoojae-validator",
    "event-handle-package",
    "array-empty-validator",
    "react-event-dependency",
    "auth-validator",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Lazarus Contagious Interview (Nov 2025)",
    reference:
      "https://socket.dev/blog/lazarus-strikes-npm-again-with-a-new-wave-of-malicious-packages",
  })),

  // ── MUT-4831 Vidar Infostealer Campaign (Oct-Nov 2025) ──
  // 17 packages delivering Vidar infostealer, masquerading as Telegram bots, icons, Cursor forks
  ...[
    "custom-tg-bot-plan",
    "custom-telegram-bot-api",
    "react-icon-pkg",
    "cursor-ai-fork",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "MUT-4831 Vidar Infostealer (Oct-Nov 2025)",
    reference:
      "https://securitylabs.datadoghq.com/articles/mut-4831-trojanized-npm-packages-vidar/",
  })),

  // ═══════════════════════════════════════════════════════════════════════════
  // OCTOBER 2025
  // ═══════════════════════════════════════════════════════════════════════════

  // ── Credential Stealer Typosquats (Oct 2025) ──
  // 10 packages impersonating popular libraries (TypeScript, Discord.js, Ethers, etc.)
  ...[
    "deezcord.js",
    "dezcord.js",
    "dizcordjs",
    "etherdjs",
    "ethesjs",
    "ethetsjs",
    "nodemonjs",
    "react-router-dom.js",
    "typescriptjs",
    "zustand.js",
  ].map((name) => ({
    name,
    versions: null,
    severity: "CRITICAL",
    campaign: "Credential Stealer Typosquats (Oct 2025)",
    reference:
      "https://thehackernews.com/2025/10/10-npm-packages-caught-stealing.html",
  })),

  // ═══════════════════════════════════════════════════════════════════════════
  // JULY 2025 - Hijacked legitimate packages (version-specific)
  // ═══════════════════════════════════════════════════════════════════════════

  // ── ESLint/Prettier Supply Chain Hijack (Jul 2025) ──
  // CVE-2025-54313: Maintainer phished, malicious versions published with node-gyp.dll malware
  {
    name: "eslint-config-prettier",
    versions: ["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
    severity: "CRITICAL",
    campaign: "ESLint/Prettier Hijack - CVE-2025-54313 (Jul 2025)",
    reference: "https://github.com/advisories/GHSA-f29h-pxvx-f335",
  },
  {
    name: "eslint-plugin-prettier",
    versions: ["4.2.2", "4.2.3"],
    severity: "CRITICAL",
    campaign: "ESLint/Prettier Hijack - CVE-2025-54313 (Jul 2025)",
    reference: "https://github.com/advisories/GHSA-f29h-pxvx-f335",
  },
  {
    name: "synckit",
    versions: ["0.11.9"],
    severity: "CRITICAL",
    campaign: "ESLint/Prettier Hijack - CVE-2025-54313 (Jul 2025)",
    reference: "https://github.com/advisories/GHSA-f29h-pxvx-f335",
  },
  {
    name: "@pkgr/core",
    versions: ["0.2.8"],
    severity: "CRITICAL",
    campaign: "ESLint/Prettier Hijack - CVE-2025-54313 (Jul 2025)",
    reference: "https://github.com/advisories/GHSA-f29h-pxvx-f335",
  },
  {
    name: "napi-postinstall",
    versions: ["0.3.1"],
    severity: "CRITICAL",
    campaign: "ESLint/Prettier Hijack - CVE-2025-54313 (Jul 2025)",
    reference: "https://github.com/advisories/GHSA-f29h-pxvx-f335",
  },
  {
    name: "got-fetch",
    versions: ["5.1.11", "5.1.12"],
    severity: "CRITICAL",
    campaign: "ESLint/Prettier Hijack - CVE-2025-54313 (Jul 2025)",
    reference: "https://github.com/advisories/GHSA-f29h-pxvx-f335",
  },
  {
    name: "is",
    versions: ["3.3.1", "5.0.0"],
    severity: "CRITICAL",
    campaign: "ESLint/Prettier Hijack - CVE-2025-54313 (Jul 2025)",
    reference: "https://github.com/advisories/GHSA-f29h-pxvx-f335",
  },
];

// ─── Build lookup structures ─────────────────────────────────────────────────

// For packages where ALL versions are bad: Set<name>
const ALL_VERSIONS_BAD = new Set();
// For packages where only specific versions are bad: Map<name, Set<version>>
const SPECIFIC_VERSIONS_BAD = new Map();
// Full info lookup: Map<name, packageInfo>
const PACKAGE_INFO = new Map();

for (const pkg of MALICIOUS_PACKAGES) {
  PACKAGE_INFO.set(pkg.name, pkg);
  if (pkg.versions === null) {
    ALL_VERSIONS_BAD.add(pkg.name);
  } else {
    SPECIFIC_VERSIONS_BAD.set(pkg.name, new Set(pkg.versions));
  }
}

// ─── CLI Argument Parsing ────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = {
    scanDir: process.cwd(),
    maxDepth: 5,
    jsonOutput: false,
    quiet: false,
    historyMonths: 6,
    skipHistory: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--depth" && i + 1 < args.length) {
      options.maxDepth = parseInt(args[++i], 10);
      if (isNaN(options.maxDepth) || options.maxDepth < 1) {
        console.error("Error: --depth must be a positive integer");
        process.exit(1);
      }
    } else if (arg === "--history-months" && i + 1 < args.length) {
      options.historyMonths = parseInt(args[++i], 10);
      if (isNaN(options.historyMonths) || options.historyMonths < 1) {
        console.error("Error: --history-months must be a positive integer");
        process.exit(1);
      }
    } else if (arg === "--no-history") {
      options.skipHistory = true;
    } else if (arg === "--json") {
      options.jsonOutput = true;
    } else if (arg === "--quiet" || arg === "-q") {
      options.quiet = true;
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else if (!arg.startsWith("-")) {
      options.scanDir = path.resolve(arg);
    } else {
      console.error(`Unknown option: ${arg}`);
      printHelp();
      process.exit(1);
    }
  }

  return options;
}

function printHelp() {
  console.log(`
Malicious NPM Package Scanner
==============================

Scans directories recursively for package.json files and checks all
dependencies against known malicious npm packages.

Usage:
  node scan-malicious-packages.js [directory] [options]

Options:
  --depth N           Maximum recursion depth (default: 5)
  --history-months N  Months of git history to check (default: 6)
  --no-history        Skip git history scanning
  --json              Output results as JSON (for CI/CD integration)
  --quiet, -q         Only show findings (suppress informational output)
  --help, -h          Show this help message

Detected Campaigns (Oct 2025 - Apr 2026):
  - Strapi Plugin Campaign (36 packages)
  - Axios Supply Chain Compromise (Sapphire Sleet)
  - Ghost Campaign (crypto wallet stealers)
  - Crypto/CI Secret Harvesters (AI tool typosquats)
  - Lazarus XPACK Campaign (North Korea)
  - dYdX & Phantom Packages Compromise
  - Solana/Ethereum Key Stealers
  - Flashbots SDK Impersonators
  - StegaBin Campaign (26 typosquats)
  - NodeCordRAT (Bitcoin typosquats)
  - Remote Codebase Wiper
  - Phishing Infrastructure Packages
  - Lazarus Contagious Interview
  - MUT-4831 Vidar Infostealer
  - Credential Stealer Typosquats
  - ESLint/Prettier Hijack (CVE-2025-54313)
`);
}

// ─── Directory Scanner ───────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "bower_components",
  ".next",
  ".nuxt",
  "dist",
  "build",
  ".cache",
  "coverage",
  "__pycache__",
  ".venv",
  "vendor",
]);

function findPackageJsonFiles(dir, maxDepth, currentDepth = 0) {
  const results = [];

  if (currentDepth > maxDepth) return results;

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (entry.name === "package.json" && entry.isFile()) {
      results.push(path.join(dir, entry.name));
    } else if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
      results.push(
        ...findPackageJsonFiles(
          path.join(dir, entry.name),
          maxDepth,
          currentDepth + 1
        )
      );
    }
  }

  return results;
}

// ─── Dependency Checker ──────────────────────────────────────────────────────

const DEP_FIELDS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
  "bundledDependencies",
  "bundleDependencies",
];

function extractVersion(versionRange) {
  // Strip semver range operators to get the base version
  // e.g. "^1.14.1" -> "1.14.1", "~0.30.4" -> "0.30.4", ">=1.0.0" -> "1.0.0"
  return versionRange.replace(/^[\^~>=<*\s]+/, "").split(/\s/)[0];
}

function checkPackageJson(filePath) {
  const findings = [];

  let content;
  try {
    content = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return findings;
  }

  for (const field of DEP_FIELDS) {
    const deps = content[field];
    if (!deps || typeof deps !== "object") continue;

    // bundledDependencies can be an array of names
    if (Array.isArray(deps)) {
      for (const depName of deps) {
        if (ALL_VERSIONS_BAD.has(depName) || SPECIFIC_VERSIONS_BAD.has(depName)) {
          const info = PACKAGE_INFO.get(depName);
          findings.push({
            file: filePath,
            dependencyField: field,
            packageName: depName,
            installedVersion: "(bundled - no version specified)",
            severity: info.severity,
            campaign: info.campaign,
            reference: info.reference,
            note: ALL_VERSIONS_BAD.has(depName)
              ? "ALL versions of this package are malicious"
              : `Malicious versions: ${[...SPECIFIC_VERSIONS_BAD.get(depName)].join(", ")}`,
          });
        }
      }
      continue;
    }

    for (const [depName, versionRange] of Object.entries(deps)) {
      if (!ALL_VERSIONS_BAD.has(depName) && !SPECIFIC_VERSIONS_BAD.has(depName)) {
        continue;
      }

      const info = PACKAGE_INFO.get(depName);

      if (ALL_VERSIONS_BAD.has(depName)) {
        // Every version is malicious
        findings.push({
          file: filePath,
          dependencyField: field,
          packageName: depName,
          installedVersion: versionRange,
          severity: info.severity,
          campaign: info.campaign,
          reference: info.reference,
          note: "ALL versions of this package are malicious",
        });
      } else {
        // Only specific versions are bad - check if the resolved version matches
        const version = extractVersion(String(versionRange));
        const badVersions = SPECIFIC_VERSIONS_BAD.get(depName);

        if (badVersions.has(version)) {
          findings.push({
            file: filePath,
            dependencyField: field,
            packageName: depName,
            installedVersion: versionRange,
            severity: info.severity,
            campaign: info.campaign,
            reference: info.reference,
            note: `Exact malicious version detected. Malicious versions: ${[...badVersions].join(", ")}`,
          });
        }
      }
    }
  }

  // Also check lockfile for exact resolved versions (package-lock.json)
  const lockfilePath = path.join(path.dirname(filePath), "package-lock.json");
  if (fs.existsSync(lockfilePath)) {
    try {
      const lockContent = JSON.parse(fs.readFileSync(lockfilePath, "utf8"));
      const lockPackages = lockContent.packages || {};
      const lockDeps = lockContent.dependencies || {};

      // Check v2/v3 lockfile format (packages field)
      for (const [pkgPath, pkgInfo] of Object.entries(lockPackages)) {
        const pkgName = pkgPath.replace(/^node_modules\//, "");
        if (!pkgName || pkgName.startsWith(".")) continue;

        if (ALL_VERSIONS_BAD.has(pkgName)) {
          const info = PACKAGE_INFO.get(pkgName);
          // Avoid duplicate if already found via package.json
          if (!findings.some((f) => f.packageName === pkgName && f.file === filePath)) {
            findings.push({
              file: lockfilePath,
              dependencyField: "lockfile (transitive)",
              packageName: pkgName,
              installedVersion: pkgInfo.version || "unknown",
              severity: info.severity,
              campaign: info.campaign,
              reference: info.reference,
              note: "Found in lockfile as transitive dependency - ALL versions malicious",
            });
          }
        } else if (SPECIFIC_VERSIONS_BAD.has(pkgName)) {
          const badVersions = SPECIFIC_VERSIONS_BAD.get(pkgName);
          if (pkgInfo.version && badVersions.has(pkgInfo.version)) {
            const info = PACKAGE_INFO.get(pkgName);
            if (!findings.some((f) => f.packageName === pkgName && f.installedVersion === pkgInfo.version && f.file === filePath)) {
              findings.push({
                file: lockfilePath,
                dependencyField: "lockfile (resolved)",
                packageName: pkgName,
                installedVersion: pkgInfo.version,
                severity: info.severity,
                campaign: info.campaign,
                reference: info.reference,
                note: `Exact malicious version resolved in lockfile. Malicious versions: ${[...badVersions].join(", ")}`,
              });
            }
          }
        }
      }

      // Check v1 lockfile format (dependencies field)
      function checkLockDeps(deps, depPath = "") {
        for (const [name, info] of Object.entries(deps)) {
          const fullName = depPath ? `${depPath} > ${name}` : name;
          if (ALL_VERSIONS_BAD.has(name)) {
            const pkgInfo = PACKAGE_INFO.get(name);
            findings.push({
              file: lockfilePath,
              dependencyField: `lockfile v1 (${fullName})`,
              packageName: name,
              installedVersion: info.version || "unknown",
              severity: pkgInfo.severity,
              campaign: pkgInfo.campaign,
              reference: pkgInfo.reference,
              note: "Found in lockfile - ALL versions malicious",
            });
          } else if (SPECIFIC_VERSIONS_BAD.has(name) && info.version) {
            const badVersions = SPECIFIC_VERSIONS_BAD.get(name);
            if (badVersions.has(info.version)) {
              const pkgInfo = PACKAGE_INFO.get(name);
              findings.push({
                file: lockfilePath,
                dependencyField: `lockfile v1 (${fullName})`,
                packageName: name,
                installedVersion: info.version,
                severity: pkgInfo.severity,
                campaign: pkgInfo.campaign,
                reference: pkgInfo.reference,
                note: `Malicious version in lockfile. Malicious versions: ${[...badVersions].join(", ")}`,
              });
            }
          }
          // Recurse into nested dependencies
          if (info.dependencies) {
            checkLockDeps(info.dependencies, fullName);
          }
        }
      }
      if (Object.keys(lockDeps).length > 0) {
        checkLockDeps(lockDeps);
      }
    } catch {
      // Lockfile parse error - skip
    }
  }

  return findings;
}

// ─── Git History Scanner ─────────────────────────────────────────────────────

function findGitRoot(filePath) {
  let dir = path.dirname(filePath);
  while (dir !== path.dirname(dir)) {
    if (fs.existsSync(path.join(dir, ".git"))) return dir;
    dir = path.dirname(dir);
  }
  return null;
}

function checkDepsInContent(content, source) {
  const findings = [];
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return findings;
  }

  for (const field of DEP_FIELDS) {
    const deps = parsed[field];
    if (!deps || typeof deps !== "object") continue;

    if (Array.isArray(deps)) {
      for (const depName of deps) {
        if (ALL_VERSIONS_BAD.has(depName) || SPECIFIC_VERSIONS_BAD.has(depName)) {
          const info = PACKAGE_INFO.get(depName);
          findings.push({
            ...source,
            dependencyField: field,
            packageName: depName,
            installedVersion: "(bundled)",
            severity: info.severity,
            campaign: info.campaign,
            reference: info.reference,
            note: ALL_VERSIONS_BAD.has(depName)
              ? "ALL versions of this package are malicious"
              : `Malicious versions: ${[...SPECIFIC_VERSIONS_BAD.get(depName)].join(", ")}`,
          });
        }
      }
      continue;
    }

    for (const [depName, versionRange] of Object.entries(deps)) {
      if (!ALL_VERSIONS_BAD.has(depName) && !SPECIFIC_VERSIONS_BAD.has(depName)) continue;
      const info = PACKAGE_INFO.get(depName);

      if (ALL_VERSIONS_BAD.has(depName)) {
        findings.push({
          ...source,
          dependencyField: field,
          packageName: depName,
          installedVersion: versionRange,
          severity: info.severity,
          campaign: info.campaign,
          reference: info.reference,
          note: "ALL versions of this package are malicious",
        });
      } else {
        const version = extractVersion(String(versionRange));
        const badVersions = SPECIFIC_VERSIONS_BAD.get(depName);
        if (badVersions.has(version)) {
          findings.push({
            ...source,
            dependencyField: field,
            packageName: depName,
            installedVersion: versionRange,
            severity: info.severity,
            campaign: info.campaign,
            reference: info.reference,
            note: `Exact malicious version detected. Malicious versions: ${[...badVersions].join(", ")}`,
          });
        }
      }
    }
  }
  return findings;
}

function checkGitHistory(packageJsonFiles, options) {
  const findings = [];
  // Group files by their git repo root to avoid redundant git-root lookups
  const repoMap = new Map(); // gitRoot -> [filePath, ...]

  for (const file of packageJsonFiles) {
    const gitRoot = findGitRoot(file);
    if (!gitRoot) continue;
    if (!repoMap.has(gitRoot)) repoMap.set(gitRoot, []);
    repoMap.get(gitRoot).push(file);
  }

  const sinceDate = `${options.historyMonths} months ago`;
  const seen = new Set(); // dedupe: "commit:file:package" combos

  for (const [gitRoot, files] of repoMap) {
    for (const file of files) {
      const relPath = path.relative(gitRoot, file).replace(/\\/g, "/");

      // Get commits that touched this file in the last N months
      let commitLog;
      try {
        commitLog = execSync(
          `git log --since="${sinceDate}" --format="%H %ai" --diff-filter=AMRD -- "${relPath}"`,
          { cwd: gitRoot, encoding: "utf8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] }
        ).trim();
      } catch {
        continue;
      }

      if (!commitLog) continue;

      const commits = commitLog.split("\n").map((line) => {
        const [hash, ...dateParts] = line.split(" ");
        return { hash, date: dateParts.join(" ") };
      });

      for (const { hash, date } of commits) {
        let content;
        try {
          content = execSync(`git show ${hash}:"${relPath}"`, {
            cwd: gitRoot,
            encoding: "utf8",
            timeout: 10000,
            stdio: ["pipe", "pipe", "pipe"],
          });
        } catch {
          continue;
        }

        const source = {
          file,
          historyCommit: hash.slice(0, 10),
          historyDate: date,
        };

        const commitFindings = checkDepsInContent(content, source);
        for (const f of commitFindings) {
          const key = `${hash}:${file}:${f.packageName}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push(f);
        }
      }
    }
  }

  return findings;
}

// ─── Output Formatting ──────────────────────────────────────────────────────

function printFinding(f) {
  const lines = [
    `  SEVERITY:  ${f.severity}`,
    `  Package:   ${f.packageName}@${f.installedVersion}`,
    `  Location:  ${f.file}`,
  ];
  if (f.historyCommit) {
    lines.push(`  Commit:    ${f.historyCommit} (${f.historyDate})`);
  }
  lines.push(
    `  Field:     ${f.dependencyField}`,
    `  Campaign:  ${f.campaign}`,
    `  Details:   ${f.note}`,
    `  Reference: ${f.reference}`
  );
  return lines.join("\n");
}

function printFindings(currentFindings, historyFindings, scannedCount, options) {
  const totalFindings = currentFindings.length + historyFindings.length;

  if (options.jsonOutput) {
    console.log(
      JSON.stringify(
        {
          scanDate: new Date().toISOString(),
          scanDirectory: options.scanDir,
          maxDepth: options.maxDepth,
          historyMonths: options.skipHistory ? 0 : options.historyMonths,
          packageJsonsScanned: scannedCount,
          currentFindings: currentFindings.length,
          historyFindings: historyFindings.length,
          totalFindings,
          findings: currentFindings,
          history: historyFindings,
        },
        null,
        2
      )
    );
    return;
  }

  if (totalFindings === 0) {
    if (!options.quiet) {
      console.log("\n  No malicious packages detected (current or history). All clean!\n");
    }
    return;
  }

  if (currentFindings.length > 0) {
    console.log(
      `\n  !! MALICIOUS PACKAGES DETECTED (CURRENT): ${currentFindings.length} finding(s) !!\n`
    );
    console.log("=".repeat(80));
    for (const f of currentFindings) {
      console.log(`\n${printFinding(f)}\n${"=".repeat(80)}`);
    }

    console.log(`
ACTION REQUIRED:
  1. Remove the malicious package(s) from your package.json
  2. Delete your node_modules directory and package-lock.json
  3. Run 'npm install' to get clean dependencies
  4. Audit your system for signs of compromise
  5. Rotate any credentials that may have been exposed
  6. Report to your security team
`);
  }

  if (historyFindings.length > 0) {
    console.log(
      `\n  !! MALICIOUS PACKAGES FOUND IN GIT HISTORY: ${historyFindings.length} finding(s) !!\n`
    );
    console.log(
      "  These packages were present in past commits. Your system may have\n" +
      "  been compromised during that period. Investigate and rotate credentials.\n"
    );
    console.log("=".repeat(80));
    for (const f of historyFindings) {
      console.log(`\n${printFinding(f)}\n${"=".repeat(80)}`);
    }

    console.log(`
HISTORY ACTION REQUIRED:
  1. Determine when the malicious package was added and removed
  2. Audit CI/CD pipelines and build servers that ran during that period
  3. Rotate ALL credentials, tokens, and API keys used in affected projects
  4. Check for unauthorized access or data exfiltration
  5. Report the incident to your security team
`);
  }

  if (currentFindings.length === 0 && historyFindings.length > 0 && !options.quiet) {
    console.log("  NOTE: No malicious packages in current files - only found in git history.\n");
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  const options = parseArgs(process.argv);

  if (!fs.existsSync(options.scanDir)) {
    console.error(`Error: Directory not found: ${options.scanDir}`);
    process.exit(1);
  }

  const showProgress = !options.quiet && !options.jsonOutput;

  if (showProgress) {
    console.log(`
Malicious NPM Package Scanner
==============================
Scan directory:  ${options.scanDir}
Max depth:       ${options.maxDepth}
Packages in DB:  ${MALICIOUS_PACKAGES.length}
Git history:     ${options.skipHistory ? "disabled" : `last ${options.historyMonths} months`}
Campaigns:       16 campaigns (Oct 2025 - Apr 2026)
`);
    console.log("Scanning current files...\n");
  }

  const packageJsonFiles = findPackageJsonFiles(options.scanDir, options.maxDepth);

  if (showProgress) {
    console.log(`Found ${packageJsonFiles.length} package.json file(s)\n`);
  }

  const currentFindings = [];

  for (const file of packageJsonFiles) {
    if (showProgress) {
      const relPath = path.relative(options.scanDir, file);
      process.stdout.write(`  Checking ${relPath}...`);
    }

    const findings = checkPackageJson(file);
    currentFindings.push(...findings);

    if (showProgress) {
      if (findings.length > 0) {
        console.log(` !! ${findings.length} FINDING(S)`);
      } else {
        console.log(" OK");
      }
    }
  }

  // Git history scan
  let historyFindings = [];

  if (!options.skipHistory) {
    if (showProgress) {
      console.log(`\nScanning git history (last ${options.historyMonths} months)...\n`);
    }
    historyFindings = checkGitHistory(packageJsonFiles, options);
    if (showProgress) {
      if (historyFindings.length > 0) {
        console.log(`  !! Found ${historyFindings.length} historical finding(s)`);
      } else {
        console.log("  No malicious packages found in git history.");
      }
    }
  }

  printFindings(currentFindings, historyFindings, packageJsonFiles.length, options);

  // Exit with code 1 if any findings detected (useful for CI/CD)
  const totalFindings = currentFindings.length + historyFindings.length;
  process.exit(totalFindings > 0 ? 1 : 0);
}

main();
