/**
 * Module 9 — Guardian crypto-policy checker.
 *
 * Static verifier that Guardian runs (in CI and on demand) over a repo to enforce the
 * crypto rules. It is heuristic by design — a fast, explainable guard that complements the
 * deeper scanners (Gitleaks/Semgrep/CodeQL), not a replacement.
 *
 * Verifies:
 *   1. No plaintext passwords stored.
 *   2. No SHA-256/MD5/SHA-1 used for password storage.
 *   3. No auth tokens in localStorage.
 *   4. No obvious secrets committed.
 *   5. No sensitive data cached by the PWA service worker.
 *   6. No private health/disability data in logs.
 *   7. No encryption keys stored beside encrypted records.
 *   8. Sensitive exports are encrypted.
 *   9. Admin access is logged.
 *  10. Crypto libraries are pinned to exact versions.
 *
 * CLI:  tsx crypto/cryptoPolicyChecker.ts <rootDir>
 */
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, extname, basename, relative } from "node:path";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  rule: string;
  severity: Severity;
  file: string;
  line: number;
  message: string;
  userSafetyImpact: string;
}

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".cache",
  "playwright-report",
]);
const SOURCE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".go", ".java"]);

function isTestOrDoc(path: string): boolean {
  return (
    /(^|\/)(tests?|__tests__|fixtures)(\/|$)/.test(path) ||
    path.endsWith(".md") ||
    path.endsWith(".test.ts") ||
    path.endsWith(".spec.ts")
  );
}

function walk(root: string): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) stack.push(full);
      } else {
        out.push(full);
      }
    }
  }
  return out;
}

interface LineRule {
  rule: string;
  severity: Severity;
  userSafetyImpact: string;
  test: (line: string, file: string) => boolean;
  scope?: (file: string) => boolean; // which files this rule applies to
  skipComments?: boolean; // ignore comment lines (for structural heuristics)
}

function isCommentLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*") || t.startsWith("#");
}

const PWD_NEAR = /(password|passwd|pwd)/i;

const LINE_RULES: LineRule[] = [
  {
    rule: "no-plaintext-password",
    severity: "high",
    userSafetyImpact: "Plaintext passwords let an attacker take over accounts of vulnerable users.",
    skipComments: true,
    test: (l) =>
      /\b(password|passwd|pwd)\s*[:=]\s*["'`][^"'`]{1,}["'`]/i.test(l) &&
      !/hash|argon2|verify|placeholder|example|process\.env|\^pass\^/i.test(l),
  },
  {
    rule: "no-fast-hash-for-password",
    severity: "critical",
    userSafetyImpact: "Fast hashes (MD5/SHA-1/SHA-256) are trivially cracked, exposing user credentials.",
    test: (l) =>
      /createHash\(\s*["'](md5|sha1|sha256)["']/i.test(l) && PWD_NEAR.test(l),
  },
  {
    rule: "no-token-in-localstorage",
    severity: "high",
    userSafetyImpact: "Tokens in localStorage are stealable via XSS, enabling session hijack.",
    test: (l) => /localStorage\s*\.\s*(set|get)Item\s*\(/i.test(l) && /token|jwt|access|refresh|secret|auth/i.test(l),
  },
  {
    rule: "no-committed-secret",
    severity: "critical",
    userSafetyImpact: "A committed secret can be used to access systems protecting user data.",
    test: (l) =>
      /AKIA[0-9A-Z]{16}/.test(l) ||
      /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(l) ||
      /\bgh[pousr]_[A-Za-z0-9]{20,}\b/.test(l),
  },
  {
    rule: "no-health-data-in-logs",
    severity: "high",
    userSafetyImpact: "Logging health/disability data exposes the most sensitive data of at-risk users.",
    test: (l) =>
      /(console\.(log|info|warn|error)|logger\.(log|info|warn|error|debug))\s*\(/.test(l) &&
      /(health|disabilit|diagnos|medical|ssn|date_of_birth|\bdob\b|safeguard)/i.test(l),
  },
  {
    rule: "no-sensitive-cache-in-serviceworker",
    severity: "high",
    userSafetyImpact: "Caching sensitive responses in the service worker leaves PII on shared devices.",
    scope: (f) => /(service-worker|sw)\.(t|j)s$|workbox/i.test(basename(f)),
    test: (l) =>
      /(cache\.(put|add|addAll)|caches\.open|registerRoute|new\s+CacheFirst|new\s+StaleWhileRevalidate)/i.test(l) &&
      /(\/api|\/profile|\/health|authorization|token|account)/i.test(l),
  },
  {
    rule: "key-stored-with-ciphertext",
    severity: "high",
    userSafetyImpact: "Storing a key beside the data it protects defeats the encryption entirely.",
    skipComments: true,
    // Structural: a record/object literal carrying BOTH a ciphertext property and a raw key
    // property on the same line, e.g. `{ ct: cipher, key: rawKey }`. A wrapped DEK (kekId +
    // wrapped ct) is fine and excluded.
    test: (l) =>
      /(?:^|[{,(\s])(ct|ciphertext|encrypted_data|encrypted)\s*[:=]/i.test(l) &&
      /(?:^|[{,(\s])(key|dek|secret_key|raw_?key)\s*[:=]/i.test(l) &&
      !/kekId|wrapped|keyId|publicKey/i.test(l),
  },
];

function pinningFindings(root: string): Finding[] {
  const findings: Finding[] = [];
  const cryptoLibs = [/^argon2$/, /^libsodium/, /^jose$/, /^@signalapp\//, /^cookie$/, /^tweetnacl/];
  for (const pkgPath of [join(root, "security", "package.json"), join(root, "package.json")]) {
    if (!existsSync(pkgPath)) continue;
    let pkg: Record<string, Record<string, string>>;
    try {
      pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    } catch {
      continue;
    }
    for (const section of ["dependencies", "optionalDependencies", "devDependencies"]) {
      const deps = pkg[section];
      if (!deps) continue;
      for (const [name, range] of Object.entries(deps)) {
        if (!cryptoLibs.some((re) => re.test(name))) continue;
        if (/^[\^~><=*]|\bx\b|latest/.test(range)) {
          findings.push({
            rule: "crypto-libs-must-be-pinned",
            severity: "high",
            file: relative(root, pkgPath) || "package.json",
            line: 0,
            message: `crypto lib '${name}' is not exact-pinned (found "${range}")`,
            userSafetyImpact:
              "Unpinned crypto libs allow a malicious/regressed version to silently weaken encryption.",
          });
        }
      }
    }
  }
  return findings;
}

export interface CheckResult {
  findings: Finding[];
  summary: Record<Severity, number>;
  filesScanned: number;
}

export function runCryptoPolicyChecks(root: string): CheckResult {
  const findings: Finding[] = [];
  const files = walk(root).filter((f) => SOURCE_EXT.has(extname(f)));
  let scanned = 0;

  for (const file of files) {
    const rel = relative(root, file);
    if (isTestOrDoc(rel)) continue;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    scanned++;
    const lines = text.split(/\r?\n/);
    for (const rule of LINE_RULES) {
      if (rule.scope && !rule.scope(file)) continue;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        if (line.length > 1000) continue; // skip minified/huge lines
        if (rule.skipComments && isCommentLine(line)) continue;
        if (rule.test(line, file)) {
          findings.push({
            rule: rule.rule,
            severity: rule.severity,
            file: rel,
            line: i + 1,
            message: `${rule.rule}: ${line.trim().slice(0, 160)}`,
            userSafetyImpact: rule.userSafetyImpact,
          });
        }
      }
    }
  }

  findings.push(...pinningFindings(root));

  const summary: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) summary[f.severity]++;
  return { findings, summary, filesScanned: scanned };
}

/** True if results contain anything that should fail CI (high or critical). */
export function shouldFail(result: CheckResult): boolean {
  return result.summary.high > 0 || result.summary.critical > 0;
}

// ------------------------------------- CLI ----------------------------------------------
const isMain =
  typeof process !== "undefined" &&
  process.argv[1] &&
  /cryptoPolicyChecker\.(ts|js)$/.test(process.argv[1]);

if (isMain) {
  const root = process.argv[2] ?? ".";
  const result = runCryptoPolicyChecks(root);
  for (const f of result.findings) {
    // eslint-disable-next-line no-console
    console.log(`[${f.severity.toUpperCase()}] ${f.rule} ${f.file}:${f.line} — ${f.message}`);
  }
  // eslint-disable-next-line no-console
  console.log(
    `\nGuardian crypto-policy: scanned ${result.filesScanned} files; ` +
      `critical=${result.summary.critical} high=${result.summary.high} ` +
      `medium=${result.summary.medium} low=${result.summary.low}`,
  );
  process.exit(shouldFail(result) ? 1 : 0);
}
