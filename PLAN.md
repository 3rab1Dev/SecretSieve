# SecretSieve - Master Implementation Plan

**Project:** SecretSieve
**Owner / Copyright:** © 3rabDev - https://3rabdev.online
**Type:** Professional, intelligent, high-performance cybersecurity CLI in Python
**Purpose:** Detect accidentally exposed secrets and sensitive credentials in source code, configuration files, project directories, and optionally Git data.
**Document status:** Planning phase - normative blueprint for implementation. No code is authorized by this document.
**Repository state at time of planning:** Greenfield. Only `assets/icon.webp` exists. No source, tests, config, packaging, docs, or license files were present.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Vision](#2-vision)
3. [Goals](#3-goals)
4. [Non-Goals](#4-non-goals)
5. [Product Principles](#5-product-principles)
6. [Privacy Model](#6-privacy-model)
7. [High-Level Architecture](#7-high-level-architecture)
8. [Detection Pipeline](#8-detection-pipeline)
9. [Detection Engines](#9-detection-engines)
10. [Signature Detection](#10-signature-detection)
11. [Entropy Detection](#11-entropy-detection)
12. [Context Analysis](#12-context-analysis)
13. [Heuristics](#13-heuristics)
14. [Confidence Model](#14-confidence-model)
15. [Severity Model](#15-severity-model)
16. [False-Positive Reduction](#16-false-positive-reduction)
17. [File Scanner](#17-file-scanner)
18. [File-Type Strategy](#18-file-type-strategy)
19. [Ignore / Exclusion Strategy](#19-ignore--exclusion-strategy)
20. [Finding Data Model](#20-finding-data-model)
21. [Rule System](#21-rule-system)
22. [Rule ID Strategy](#22-rule-id-strategy)
23. [CLI Architecture](#23-cli-architecture)
24. [CLI Commands](#24-cli-commands)
25. [CLI UX](#25-cli-ux)
26. [Output Formats](#26-output-formats)
27. [Exit Codes](#27-exit-codes)
28. [Configuration System](#28-configuration-system)
29. [Custom Rules](#29-custom-rules)
30. [Git Integration](#30-git-integration)
31. [Performance Architecture](#31-performance-architecture)
32. [Security of SecretSieve](#32-security-of-secretsieve)
33. [Testing Strategy](#33-testing-strategy)
34. [Security Testing](#34-security-testing)
35. [Performance Testing](#35-performance-testing)
36. [Python Architecture](#36-python-architecture)
37. [Dependency Strategy](#37-dependency-strategy)
38. [Repository Structure](#38-repository-structure)
39. [Branding](#39-branding)
40. [Copyright](#40-copyright)
41. [MVP Scope](#41-mvp-scope)
42. [v1.0 Scope](#42-v10-scope)
43. [Future Roadmap](#43-future-roadmap)
44. [Development Phases](#44-development-phases)
45. [Risks and Mitigations](#45-risks-and-mitigations)
46. [Acceptance Criteria](#46-acceptance-criteria)
47. [Definition of Done](#47-definition-of-done)
48. [Release Strategy](#48-release-strategy)

---

## 1. Project Overview

SecretSieve is a local-first Python CLI that scans a given path (file or directory tree) and separates normal code/configuration from potentially sensitive credentials.

Scope of detection (conceptual, prioritized in §10):

- Cloud provider keys (AWS, GCP, Azure-style connection strings)
- Developer platform tokens (GitHub, GitLab, npm, PyPI)
- Communication tokens (Slack, Discord)
- Payment keys (Stripe)
- Generic auth material (JWT, Bearer tokens, OAuth secrets, API keys, webhook secrets)
- Database credentials and connection strings
- Private keys (SSH, PEM/PKCS, OpenSSL artifacts)
- Environment-file secrets and generic password assignments

The product is **not a regex script**. It is a multi-signal engine:

```mermaid
flowchart TD
    A[Input path] --> B[Path discovery]
    B --> C[File filtering + exclusions]
    C --> D[Binary / size / encoding gate]
    D --> E[Text decoding + line indexing]
    E --> F[Candidate extraction]
    F --> G[Signature detection]
    F --> H[Entropy analysis]
    F --> I[Context analysis]
    G --> J[Heuristics + FP filters]
    H --> J
    I --> J
    J --> K[Confidence scoring]
    K --> L[Severity assignment]
    L --> M[Deduplication + normalization]
    M --> N[Reporter: human / JSON]
    N --> O[Exit code]
```

Current repository reality: there is no code to refactor. This plan therefore defines the initial architecture, not a migration.

---

## 2. Vision

SecretSieve acts like an intelligent sieve:

> Project → File discovery → File filtering → Content analysis → Detection engines → Context analysis → Entropy analysis → Confidence scoring → Severity scoring → False-positive reduction → Deduplication → Finding normalization → Professional reporting.

User experience vision:

- A developer can run `secretsieve .` in under a second on a typical repo and trust the result.
- A security researcher can run `secretsieve --json --fail-on high ./src` in CI and gate merges deterministically.
- Neither user ever sees a full secret value in normal output.
- Every finding explains *why* it fired and how confident the tool is, without fake "AI" mystique.
- The tool is visibly distinguishable from a 50-line regex scanner by its structure, scoring, redaction, tests, and docs.

---

## 3. Goals

1. **Security:** never leak secrets via output, logs, errors, or debug flags.
2. **Intelligence:** combine signatures + entropy + context + heuristics + deterministic scoring.
3. **Accuracy:** optimize precision (low FP) without collapsing recall; every rule ships with positive and negative fixtures.
4. **Speed:** scan a 500-file / 20 MB repo in well under 2 s on a commodity laptop (to be benchmarked, not promised - see §35).
5. **Maintainability:** small, explicit modules with single responsibilities; rule changes do not require engine changes.
6. **Extensibility:** new provider = new rule module + tests, no core edits.
7. **Professional CLI UX:** clean default output, `--quiet` for CI, `--verbose`/`--json` for investigation.
8. **Privacy:** 100% local by default; no network, no telemetry, no verification calls.
9. **CI compatibility:** stable exit codes, stable JSON schema, `--fail-on`, deterministic ordering.
10. **Easy installation:** `pip install secretsieve` / `pipx install secretsieve` with zero mandatory runtime dependencies in MVP.
11. **Easy future expansion:** Git-aware scanning, custom rules, SARIF support designed as additive layers, not rewrites.

---

## 4. Non-Goals

Explicitly out of scope (at least for MVP/v1.0):

1. **No secret verification.** SecretSieve MUST NOT call AWS/G GitHub/Stripe APIs to "check if the key is live." Rationale: privacy, safety (would transmit secrets), credential-burn risk, offline requirement, CI flakiness.
2. **No auto-remediation.** No rewriting files, no rotation, no vault writes. Report only.
3. **No network features in core scan.** No update checks, no telemetry, no cloud rule feed, no external API.
4. **No GitHub Actions product.** Per project constraint, no `.github/workflows` will be designed, shipped, or documented as a milestone. Generic CI compatibility (exit codes + JSON) is the goal instead.
5. **No binary / compiled artifact secret extraction.** PE/ELF/Mach-O string extraction, OCR, image steganography are out of scope.
6. **No DLP / endpoint agent.** No filesystem watcher daemon, no IDE plugin in MVP/v1.0.
7. **No "AI" classifier dependency.** No ML model download, no embeddings, no LLM calls. "Intelligent" means engineered multi-signal scoring, not a black-box model.
8. **No secret management.** Not a vault, not a generator, not a rotation tool.

---

## 5. Product Principles

1. **Local-first, always.** If a feature requires network, it is optional, explicit, and off by default.
2. **Redact by default.** The safest output is the default output.
3. **Deterministic.** Same input + same config + same version = same findings in same order. No randomness, no wall-clock in scoring, no hash-map iteration order leaks.
4. **Explainable.** Every finding carries `rule_id`, `reason_codes`, `confidence`, and human-readable `reason`. A user can run `secretsieve explain SS-AWS-001` and understand the rule.
5. **Precision over volume.** Ten actionable findings beat one hundred noisy ones. A rule with unmanageable FP rate does not ship or ships at LOW/INFO with aggressive FP filters.
6. **Fail closed on errors, fail open on output.** Scanner errors (unreadable file, bad config) must surface as warnings/exit code 2, never silently skip without accounting, and never dump raw content.
7. **Boring technology.** Stdlib-first, compiled regexes, streaming I/O, no clever concurrency in MVP.
8. **Rule quality is a feature.** Each rule has owner metadata, severity rationale, FP notes, positive/negative tests, and remediation text.

---

## 6. Privacy Model

Normative privacy guarantees (MUST statements for implementation):

1. **MUST NOT require internet for basic scanning.** The scan path (`discover → detect → report`) performs zero socket operations. Implementation MUST NOT import socket/requests/urllib network paths in the scan hot path; a static import audit test MUST enforce this.
2. **MUST NOT upload source code anywhere.** No code path may transmit file contents.
3. **MUST NOT transmit detected secrets externally.** Since no verification calls exist, there is no code path that sends a candidate value anywhere.
4. **MUST NOT enable telemetry by default.** No telemetry code ships in MVP. If ever added (future), it MUST be opt-in, documented, and show exactly what is sent. This plan recommends never adding it.
5. **MUST NOT require third-party verification.** Core scanner works fully offline.
6. **Future network functionality (if any) MUST be optional and explicit.** Hypothetical examples: `--check-update` or custom rule feed. Each MUST be a separate opt-in flag, MUST print what it will contact before doing so, and MUST never send findings.
7. **Privacy acceptance tests:** (a) run full scan with loopback/network disabled - must succeed; (b) static grep for `socket`, `requests`, `urllib.request.urlopen`, `http.client` in `src/secretsieve/scanner|detectors|analyzers` - must return zero hits in MVP; (c) JSON output must contain no raw secret (property test over corpus).

---

## 7. High-Level Architecture

Logical packages (detailed in §36). Data flows one way; no cycles.

```mermaid
flowchart LR
    subgraph CLI["cli/"]
        P[Parser] --> S[Scan controller]
        S --> R[Reporter]
    end
    subgraph SCAN["scanner/"]
        D[Discovery] --> F[File filter]
        F --> G[Gating: binary/size/encoding]
        G --> L[Line reader]
    end
    subgraph DETECT["detectors/ + rules/"]
        SIG[Signature engine]
        ENT[Entropy analyzer]
        CTX[Context analyzer]
        HEU[Heuristics / FP filters]
    end
    subgraph CORE["models/"]
        FIND[Finding]
        RULE[Rule]
        CONF[Config]
    end
    S --> D
    L --> SIG
    L --> ENT
    L --> CTX
    SIG --> HEU
    ENT --> HEU
    CTX --> HEU
    HEU --> FIND
    FIND --> R
    CONF --> S
    CONF --> F
    CONF --> HEU
    RULE --> SIG
```

Key design decisions:

- **Synchronous pipeline per file, sequential across files in MVP.** No threads/async in MVP. Concurrency is a v1.0+ optimization behind a flag, only if benchmarks prove need.
- **Line-oriented analysis.** All detectors operate on (line, line_no, col) tuples plus a bounded context window (±2 lines or ±200 chars). This keeps columns accurate, errors local, and memory flat.
- **Rules are data + small functions, not a DSL interpreter.** Each rule = Python module exporting a `Rule` object with precompiled regex + optional validator + metadata. Rationale: type-checked, testable, no new language to secure, no config-injection RCE surface.
- **Config is input, never code.** `secretsieve.toml` is parsed with `tomllib` only; no `eval`, no dynamic imports from config paths (custom-rule loading is sandboxed in §29).

---

## 8. Detection Pipeline

Normative order of operations (MUST be implemented in this order; rationale follows each stage):

| # | Stage | What happens | Why this position |
|---|-------|--------------|-------------------|
| 1 | Input resolution | Resolve CLI paths to abs paths; reject non-existent; detect file vs dir | Fail fast on user error before any I/O walk |
| 2 | Path discovery | Recursive `os.scandir` walk, symlink policy enforced, hidden-file policy enforced | Single enumeration point; all exclusion logic lives here, not scattered |
| 3 | File filtering | Apply include globs, exclude globs, default exclusions, size gate (stat first) | Avoid opening files that will be skipped (perf + safety) |
| 4 | Binary detection | Read first 8 KiB; if NUL byte present → mark binary, skip content (count as skipped) | Prevents binary garbage from polluting entropy/candidates |
| 5 | Text decoding | Stream-decode as UTF-8 (`errors=replace`), with per-file fallback try of `utf-8-sig`; hard cap `max_file_bytes` (default 5 MB) and `max_line_len` (default 100 KB, truncate + flag) | Bounds memory; survives Latin-1/CP1252/odd encodings without crashing |
| 6 | Candidate extraction | Per line: (a) run signature regexes; (b) extract generic quoted/assignment values for entropy path | Signatures first because they are cheapest to confirm and calibrate entropy |
| 7 | Signature detection | Match + structural validator (length, alphabet, checksum/prefix where applicable, e.g. JWT 3-segment Base64URL, PEM headers) | Validators kill 80% of naive-regex FPs at negligible cost |
| 8 | Context analysis | For each candidate, inspect key name left of `=|:`, same-line prefix, file name, dir name | Context adjusts confidence before entropy so entropy threshold can be context-sensitive |
| 9 | Entropy analysis | Compute Shannon entropy on candidate value only (quotes/whitespace stripped), compare to per-encoding thresholds | Runs only on candidates, not whole file - the main perf win |
| 10 | Heuristics / FP filters | Placeholder, example, test-fixture, hash/UUID, URL-path, minified-file, allowlist, inline-ignore checks | After scoring signals exist so filters can be precise (e.g. "high entropy BUT looks like SHA256 in test fixture → drop") |
| 11 | Confidence calculation | Deterministic weighted combination (§14) | Needs all signals present |
| 12 | Severity assignment | Lookup from rule + optional context escalation cap (§15) | Severity is intrinsic; must not be inflated by confidence |
| 13 | Deduplication | Fingerprint dedup within and across files | Prevents same secret on 50 lines of lockfile from spamming output |
| 14 | Finding creation | Build immutable `Finding` with redacted preview + reason codes | Redaction happens at construction, so reporters cannot accidentally leak |
| 15 | Reporting | Sort deterministically (severity rank → confidence desc → path → line → col), render human or JSON, compute exit code | Sorting guarantees stable CI diffs |

Pipeline invariants:

- A failure in one file MUST NOT abort the scan; record `files_errored`, continue, exit 2 only if no findings but errors occurred? No - see §27: errors always surface; exit 2 takes precedence over 0 but not over 1? Decision: if findings ≥ fail threshold → exit 1 regardless of non-fatal file errors (errors still listed). If no qualifying findings but errors occurred → exit 2. Fully fatal (bad config, bad path) → exit 2 immediately.
- Maximum per-file work is bounded: `max_file_bytes`, `max_line_len`, `max_candidates_per_file` (default 500), `max_findings_per_file` (default 100). Excess is truncated and counted in `stats.truncated_files`.

---

## 9. Detection Engines

Three cooperating engines + one filter layer. No engine alone creates a finding (except a small set of "high-precision signatures" that may fire standalone at high confidence - explicitly listed in §10).

```mermaid
flowchart TD
    C[Candidate value + span] --> S{Signature?}
    S -- yes + validator pass --> P1[provisional: base conf by rule]
    S -- no --> P2[provisional: generic path]
    C --> X[Context features]
    C --> E[Entropy features]
    P1 --> H[Heuristic + FP gate]
    P2 --> H
    X --> H
    E --> H
    H -->|pass| F[Finding]
    H -->|filtered| DROP[Dropped + counted]
```

Engine responsibilities:

- **Signature engine (§10):** high recall on known formats, high precision where structure allows.
- **Entropy analyzer (§11):** catches unknown/random-looking assigned values that no signature knows.
- **Context analyzer (§12):** modulates confidence; never fires alone.
- **Heuristics / FP layer (§13 + §16):** veto power. Any engine output can be killed here with a logged `suppress_reason` (counted in `--verbose` stats, never shown with secret content).

---

## 10. Signature Detection

### 10.1 Rule representation

Each signature rule contains: fixed prefix/structure + alphabet + length constraints + optional checksum/format validator. Regexes MUST be linear-time (no nested quantifiers, no backtracking-prone alternation); all patterns are precompiled once at startup and reused.

Generic regex hygiene: use concrete character classes (`[A-Za-z0-9_-]`), bounded repetitions (`{20,60}`), anchored affixes where possible, `re.ASCII` where appropriate. Every pattern ships with a ReDoS review checklist result in its test file.

### 10.2 MVP rule priority (ship order, not severity order)

Priority is by **precision × impact × prevalence**. MVP ships Tier 1 only (~14 rules). Tier 2 is v1.0. Tier 3 is future.

**Tier 1 - MVP (must ship):**

| Rule ID | Provider / type | Signature essence | Severity (initial) | Notes |
|---------|-----------------|-------------------|--------------------|-------|
| SS-AWS-001 | AWS Access Key ID | `AKIA[0-9A-Z]{16}` | HIGH | 20-char, fixed prefix; validator: length+alphabet only |
| SS-AWS-002 | AWS Secret Access Key | assignment-adjacent 40-char Base64-ish `[A-Za-z0-9/+=]{40}` with aws context required | CRITICAL | MUST require context (`aws_secret`, `secretaccesskey`, etc.) or paired AKIA in same file; never fire standalone |
| SS-GITHUB-001 | GitHub token | `ghp_[A-Za-z0-9]{36,}` + `gho_`, `github_pat_` variants | CRITICAL | Prefix-anchored; high precision |
| SS-GENERIC-JWT-001 (alias SS-JWT-001) | JWT | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` + 3-segment validator + base64url-decodable header | HIGH | Validator must decode header JSON and check `alg`/`typ`; rejected if not decodable |
| SS-PRIVATE-KEY-001 | PEM private key | `-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----` | CRITICAL | Block rule: captures header line; redaction shows header only |
| SS-GENERIC-001 | Generic API key assignment | `(api[_-]?key\|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{16,})['\"]?` | MEDIUM | Requires entropy ≥ threshold AND not placeholder; never HIGH alone |
| SS-GENERIC-002 | Generic secret/password assignment | `(secret\|passwd\|password\|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]` +长度/entropy gate | MEDIUM | Empty/dummy values filtered; see §16 |
| SS-DB-001 | Database URL | `(postgres|mysql|mongodb|redis|amqp)://[^/\s:]+:[^@\s/]+@[^\s'\";]+` | CRITICAL | Validator: must contain `user:pass@`; redact password segment only |
| SS-SLACK-001 | Slack token | `xox[bpas]-[A-Za-z0-9-]{10,}` | HIGH | Prefix-anchored |
| SS-STRIPE-001 | Stripe key | `(sk|pk)_(live|test)_[A-Za-z0-9]{16,}` | CRITICAL if `sk_live`, HIGH if `sk_test`, MEDIUM if `pk_*` | Severity branches inside one rule |
| SS-DISCORD-001 | Discord token | `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}` (classic) - narrow | HIGH | Known FP-prone; requires entropy+length gate |
| SS-GENERIC-003 | Bearer/OAuth header | `(?i)bearer\s+[A-Za-z0-9_\-.~+/=]{20,}` | HIGH | Requires header/auth context |
| SS-GENERIC-004 | Webhook/connection secret | `(webhook[_-]?secret\|client[_-]?secret)\s*[:=].{8,}` + entropy gate | HIGH | Context-required |
| SS-ENV-001 | `.env`-style assignment with secret-like key | file-name gated (`*.env*`, `*.env.example` excluded to INFO) + key-name gate + value gate | MEDIUM | `.env.example` findings capped at INFO |

**Tier 2 - v1.0 (designed now, built later):** Google API key (`AIza`), GCP service-account JSON (`"type": "service_account"` + `private_key`), Azure connection string, GitLab PAT (`glpat-`), npm (`npm_`), PyPI (`pypi-`), OpenAI (`sk-` disambiguated from Stripe by context/length), SendGrid, Twilio, SSH `id_rsa` content sniff, TOML/YAML nested secret keys, Dockerfile `ARG`/`ENV` secrets, shell `export SECRET=` patterns.

**Tier 3 - future:** cloud-specific checksum validators, org-specific custom packs, SARIF rule metadata export.

### 10.3 Standalone vs context-required

- **Standalone-capable (may fire without context):** SS-AWS-001, SS-GITHUB-001, SS-PRIVATE-KEY-001, SS-SLACK-001, SS-STRIPE-001, SS-JWT-001 (with validator), SS-DB-001. These have strong intrinsic structure.
- **Context-required (MUST have supporting context or entropy):** SS-AWS-002, SS-GENERIC-001/002/003/004, SS-ENV-001. Without context they are candidates only, never findings.

---

## 11. Entropy Detection

### 11.1 Method: Shannon entropy (justification)

Use **Shannon entropy** `H = -Σ p(x)·log2 p(x)` over the candidate string. Justification: simple, dependency-free, well-understood, deterministic, fast (single pass + 256-bin histogram), sufficient when combined with context. Alternatives considered and rejected: gzip-ratio (slower, less interpretable), NIST tests (overkill), ML perplexity (non-deterministic, heavy).

Normalized variants are NOT used for scoring; raw bits/char is the score. Rationale: normalized entropy hides length signal; length gates are handled separately.

### 11.2 Candidate extraction (normative)

Entropy is NEVER computed on whole lines or whole files. Candidates are extracted by:

1. Quoted-string extractor: `'...'`, `"..."`, backticks, with escapes handled, max captured length 512 chars. Unquoted `.env` values (`KEY=value`) also captured.
2. Minimum raw length **16** chars, maximum **512** chars (longer is truncated and flagged `truncated:true`; entropy computed on first 512).
3. Strip surrounding quotes/whitespace; require at least 2 character classes present (e.g. lower+upper, alpha+digit, any+symbol) OR length ≥ 32 with single-class high-entropy alphabet (hex/base64) - prevents `aaaaaaaaaaaaaaaa` from scoring.
4. Skip if candidate matches hash/UUID/placeholder gates BEFORE entropy (§16) to save cycles.

Character classes tracked: `lower, upper, digit, symbol, whitespace, non_ascii`. Encoding guess: `hex` (^[0-9a-fA-F]+$), `base64` (alphabet + `=` padding + length % 4), `base64url`, `uuid`, `other`.

### 11.3 Thresholds (initial values to be tuned on corpus, not hard promises)

| Encoding guess | Min length | Entropy threshold (bits/char) | Context modifier |
|----------------|-----------|-------------------------------|------------------|
| base64 / base64url | ≥ 20 | ≥ 4.5 | −0.4 if strong secret context (`api_key`, `secret`, `token`, `password`, `auth`), +0.5 if benign context (`example`, `test`, `placeholder`, `hash`, `id`) |
| hex | ≥ 32 | ≥ 3.7 | Same modifiers; hex ≥ 64 chars with hash filename context → auto-suppress as likely digest |
| other / mixed | ≥ 16 | ≥ 4.0 | Context required: without suspicious context, entropy alone never creates a finding (candidate only) |

Tuning protocol (not fake numbers): thresholds ship as config defaults (`[entropy]`), and Phase 4 MUST run a tuning pass over the labeled corpus (§33) reporting precision/recall per threshold step of 0.1. Final values locked before v1.0; changes after v1.0 follow semver (threshold change = minor version bump + changelog entry).

### 11.4 Confidence contribution

Entropy contributes additively to confidence (§14), never as a binary trigger:

- `entropy_margin = measured_H − effective_threshold`
- `+0 pts` if margin < 0 (gate fail → generic path cannot fire)
- `+5 pts` if 0 ≤ margin < 0.5
- `+10 pts` if 0.5 ≤ margin < 1.0
- `+15 pts` if margin ≥ 1.0
- Capped so entropy alone cannot push a generic candidate above 75% without context.

### 11.5 Special cases (normative handling)

- **Hashes (MD5/SHA1/SHA256):** recognized by `^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$` + optional hash-context (`md5`, `sha256`, `digest`, `checksum`, `etag`). Action: suppress to INFO at most, default suppress entirely unless secret context present. Rationale: hashes are not reversible credentials.
- **UUIDs:** `^[0-9a-fA-F]{8}-...` v1–v5 pattern → suppress unless key name is secret-like AND entropy high AND length beyond UUID (e.g. UUID embedded in longer token is still evaluated on full value).
- **IDs / slugs / public identifiers:** `AKIA`-like prefixes are secrets; but `arn:aws:iam::123456789012:user/...` numeric IDs, `cus_...` Stripe customer IDs, sequential integers → never findings.
- **Minified code:** files matching `*.min.js`, `*.bundle.js`, or single line > 10 KB with low newline density are flagged `generated:true`; entropy thresholds raised by +0.5 and generic rules require strong context. Rationale: bundled hashes/chunks are high-entropy non-secrets.
- **Generated content:** lockfiles, source maps, `*.snap`, coverage output → same treatment; lockfile tokens that ARE secrets (npm auth tokens in `.npmrc`) are caught by signature rules, not generic entropy.
- **Random-looking non-secrets:** CSRF nonces in templates, webpack hashes, SVG data URIs, base64 images (`data:image/...;base64,`) → explicit exclusion patterns run before entropy.

Core slogan for implementation comments/docs: *"High entropy + suspicious context + useful structural signals = strong candidate. High entropy alone = nothing."*

---

## 12. Context Analysis

### 12.1 Signal sources (in priority order)

1. **Assignment key name** (strongest): text left of `=`/`:`/`=>` on same line, normalized lowercase, split on `_-.`. Lookup in three sets: `SECRET_HINTS`, `BENIGN_HINTS`, `NEUTRAL`.
2. **Same-line prefix/suffix:** `Authorization: Bearer`, `api_key=`, `--password`, `"client_secret":`, `export AWS_SECRET...`.
3. **Structured parent keys:** JSON/YAML/TOML key path (e.g. `auth.token`, `database.password`). Implementation: lightweight line-local key extraction (no full YAML parse in MVP - regex key capture + indentation-agnostic; full parse is v1.0+ and must be safe-parse only).
4. **File name + directory name:** `.env`, `credentials.json`, `secrets.yaml`, `id_rsa`, `*.pem`, `config/prod/` raise prior; `test/`, `fixture/`, `example/`, `docs/`, `*.example`, `*.sample`, `__tests__/` lower prior.
5. **Comments:** `# real prod key`, `// TODO: replace placeholder` - weak signal, only tie-breaker.
6. **Provider-specific context:** `aws_`, `github`, `stripe`, `slack`, `discord` tokens near matching key names boost provider rule confidence.

### 12.2 Keyword sets (initial, extensible via config)

- `SECRET_HINTS` (≈40): `api_key apikey secret secret_key client_secret auth_token access_token bearer token password passwd pwd db_password database_url connection_string private_key webhook_secret stripe_secret aws_secret github_token slack_token discord_token oauth_secret`.
- `BENIGN_HINTS` (≈30): `example placeholder dummy sample test fixture mock template placeholder_value not_a_real_key your_key_here changeme xxx lorem`.
- Surrounding-syntax bonus: value is quoted + assignment operator present + secret hint within 60 chars left → strongest context tier.

### 12.3 Anti-naive rule (normative)

Containing `key`, `token`, or `password` MUST NOT auto-flag. Decision table:

| Key contains | Value looks like | Context tier | Outcome |
|--------------|-----------------|--------------|---------|
| `monkey`, `keyboard` (substring `key` but not a secret hint token) | anything | none | Tokenized match required: split on `_ - .` and match whole tokens only, so `monkey` ≠ `key`. No finding. |
| `api_key` | `test123`, `changeme`, `""` | placeholder | Suppressed (logged) |
| `api_key` | `Ab3x...` 24 chars H=4.7 | strong | Generic finding, confidence ≈ 80% |
| `keyboard_shortcut` | high-entropy | none | No finding (no token match) |
| `token` in prose docs (`tokenize.md`) | any | benign file context | Capped at INFO or suppressed |

Implementation: key normalization + whole-token set membership, never substring search.

### 12.4 Context contribution

- Strong secret context: **+15** confidence (signature path) / **required gate** (generic path).
- Weak context (auth-adjacent word within 200 chars, secret filename): **+7**.
- Benign context: **−20** and cap confidence at 60%; test/fixture/example file: cap at 50% and demote severity one level (min LOW).
- No context: **+0**; generic path cannot fire.

---

## 13. Heuristics

Deterministic structural checks applied between detection and scoring (all cheap, all unit-tested):

1. **Length/shape validator per rule** (e.g. JWT header JSON decode, AWS key length, PEM footer presence).
2. **Alphabet validator:** reject candidates with whitespace/control chars inside where the format forbids them.
3. **Paired-credential booster:** AKIA + 40-char secret in same file within 50 lines → both +10 confidence, link via `related_to` fingerprint.
4. **Connection-string parser:** split `scheme://user:pass@host/...`; require non-empty user AND pass AND host; redact pass only.
5. **Quoting/assignment shape:** unquoted bare words in code (`password = hunter2` without quotes in Python) still evaluated; shell `export X=` handled.
6. **Multi-line PEM spanning:** PEM rule consumes header + following base64 lines until footer (bounded at 100 lines / 16 KB) as ONE finding, not N line findings.
7. **Repeated-value collapsers:** same value 10+ times in one file (e.g. placeholder) → auto-suppress after 3rd occurrence with `repeated_placeholder` reason.
8. **Data-URI / image / font exclusion:** `data:(image|font|video)/...;base64,` prefix → skip entropy entirely.

---

## 14. Confidence Model

### 14.1 Semantics

- **Confidence** = estimated probability the finding is a real, usable secret (precision signal).
- **Severity** (§15) = estimated impact if real (impact signal).
- They are orthogonal. `CRITICAL + 62%` means "would be devastating if real, but we're unsure." `LOW + 98%` means "definitely a hardcoded test password, low blast radius."

Confidence is an integer 0–100, deterministic, explainable via `reason_codes`.

### 14.2 Formula (normative for MVP)

```
base = rule.base_confidence            # 70-95 for standalone signatures, 30 for generic path
ctx  = +15 strong secret ctx | +7 weak ctx | 0 none | -20 benign ctx
ent  = +0/+5/+10/+15 by margin (§11.4) # 0 for standalone sigs unless generic
struct = +5 validator pass (JWT decode, PEM footer, DB parse) | 0
pair = +10 if paired credential found (AWS AKIA+secret only in MVP)
penalty = -25 placeholder/example | -15 hash/uuid-like | -10 test/fixture path | -10 minified/generated
confidence = clamp(base + ctx + ent + struct + pair + penalty, 0, 99)
```

Never 100. Rationale: no scanner is certain; 99 cap communicates residual risk honestly.

`base_confidence` per MVP rule: private key 95, GitHub/AWS-ID/Slack/Stripe-live 90, JWT 85, DB-URL 88, Bearer 80, AWS-secret 75 (context-required), generic 30.

### 14.3 Classification bands (display + filtering)

- `very-high`: 90–99
- `high`: 75–89
- `medium`: 50–74
- `low`: 0–49

CLI `--min-confidence 75` filters below threshold (default: no filter; all findings shown; `--fail-on` uses severity, not confidence, to avoid conflating axes).

### 14.4 Example calculations (for tests to lock)

- `AKIAIOSFODNN7EXAMPLE` in `docs/example.md` with `example` value → base 90 − 20 benign − 25 placeholder → clamped low → suppressed (placeholder list contains `EXAMPLE` pattern) → zero findings. Test MUST assert suppression.
- `ghp_abcdefghijklmnopqrstuvwxyz1234567890` in `.env` as `GITHUB_TOKEN=...` → 90 + 15 ctx + 5 struct → 99 (clamped) → CRITICAL 99%.
- `password = "hunter2"` in `config.py` → generic base 30 + 15 ctx + 0 ent (H low) → 45 → LOW 45% finding (visible, not gating by default).

Every band MUST have locked unit tests with hand-computed expectations.

---

## 15. Severity Model

### 15.1 Severity ≠ confidence (normative)

Severity is assigned **solely from rule + value-subtype + deployment context**, never from entropy or confidence. Confidence answers "is it real?"; severity answers "how bad if real?".

### 15.2 Levels

| Level | Meaning | CI default weight |
|-------|---------|-------------------|
| CRITICAL | Direct auth / impersonation / infra takeover / money movement / decryption capability | Fails any `--fail-on` at `medium` or higher; always fails default |
| HIGH | Powerful credential with scope limits, or CRITICAL-class in test context | Fails `--fail-on high` and above |
| MEDIUM | Generic secret, dev/test credential, or weak-but-real password | Fails `--fail-on medium` and above |
| LOW | Likely real but minimal blast radius (test password, placeholder-adjacent, example-file credential) | Fails only `--fail-on low` |
| INFO | Informational (hash, UUID, `.env.example` placeholder shape) - off by default, shown with `--verbose` or `--severity info` | Never fails CI |

### 15.3 Initial mapping (MVP)

- CRITICAL: private key, AWS secret key (with context), GitHub token, `sk_live` Stripe, database URL with password, GCP service-account (v1.0).
- HIGH: AWS access key ID alone, JWT, Bearer, Slack, Discord, `sk_test`, webhook/client secret, OAuth client secret.
- MEDIUM: generic API key/secret assignment (real-looking), `.env` secret assignment, `pk_live`.
- LOW: short passwords, `pk_test`, test-file credentials that still look real.
- INFO: hashes, UUIDs, `.env.example` shapes, documentation placeholders (suppressed by default; visible only on request).

### 15.4 Context escalation caps (prevent inflation)

- Test/fixture/example path: severity demoted one level (CRITICAL→HIGH max), confidence capped 50. Rationale: prod impact unlikely; still worth surfacing.
- Documentation (`.md`, `docs/`): demote one level unless private-key block (keys in docs are still CRITICAL - exfiltrated docs leak).
- Minified/generated: demote one level; generic findings suppressed.
- Severity is NEVER escalated by confidence. A 99% generic password stays MEDIUM/LOW.

---

## 16. False-Positive Reduction

First-class subsystem, not an afterthought. Ordered gates (first match wins, logged as `suppress_reason`):

1. **Placeholder / example values (highest priority):** case-insensitive exact/substring match against curated set: `example`, `sample`, `placeholder`, `dummy`, `changeme`, `yourkeyhere`, `testkey`, `xxx`, `abcdef`, `123456`, `password123`, `fake`, `mock`, `todo`, `replace_me`, `insert_key_here`, plus `AKIA...EXAMPLE` (AWS documented example), `ghp_example`, repeated-char (`aaaa...`, `1111...`), sequential (`abcd1234`, `qwerty`). Config-extensible `allow.placeholder_values`.
2. **Empty / default values:** `""`, `''`, `null`, `none`, `undefined`, `changeme`, `admin/admin`, `root/root`, `password=` (empty) → suppress.
3. **Documentation detection:** file path contains `docs/`, `*.md` AND value in placeholder set → suppress; else demote (see §15.4).
4. **Known-safe patterns:** UUIDs, hashes (MD5/SHA1/SHA256), timestamps, semantic versions, color hex (`#fff`, `#ff0000` with css context), slugs.
5. **Test-fixture awareness:** path segments `test`, `tests`, `testing`, `fixture`, `fixtures`, `mock`, `__tests__`, `e2e`, `spec` → demote + cap, plus `test_`/`mock_` value prefix → suppress.
6. **Rule-specific exclusions:** e.g. Stripe `pk_test` never CRITICAL; JWT with `alg:none` flagged distinctly (unsigned - HIGH, reason `unsigned_jwt`); DB URL with `localhost` + `root:root` → LOW.
7. **Allowlisting (config + inline):**
   - Config `[[allow.fingerprint]]` by finding fingerprint (preferred, stable across edits).
   - Config `[[allow.path_rule]]` by (rule_id + path glob).
   - Inline ignore: trailing comment `# secretsieve:ignore` or `// secretsieve:ignore` on the SAME line suppresses that line only for the NEXT scan; MUST require exact token `secretsieve:ignore` (no `ignore-all`, no file-level blanket in MVP). **Security implications (must be documented):** inline ignores are visible in diffs, suppress only one line, are logged in `--verbose` stats (`suppressed_by_ignore`), and `--strict` mode (future) can fail CI if any ignore is present. Never support bare `nolint`/`skip` synonyms (auditability).
8. **Generated-file detection:** `*.min.js`, `*.bundle.js`, `package-lock.json`, `yarn.lock`, `*.map`, `*.snap`, `coverage/`, single-line > 10 KB → thresholds raised / generic suppressed.
9. **Minified-file handling:** as above + cap findings per file + mark `generated:true` in JSON.
10. **Hash/UUID recognition:** §11.5.
11. **Common public identifiers:** AWS `EXAMPLE`, Stripe `pk_test_...` docs keys, GitHub `ghp_...` docs examples list, `arn:aws:iam::` numeric, customer IDs.
12. **Obvious dummy strings:** length < 8 for passwords, all-alpha lowercase dictionary words (`password`, `secret`, `hunter2` IS flagged LOW - real hardcoded password - but `mypassword` in tutorial prose without assignment is not).

All suppressions increment `stats.suppressed_by_<reason>` for `--verbose` audit. Nothing is silently dropped.

---

## 17. File Scanner

Normative behaviors:

- **Recursive traversal:** `os.scandir`-based iterative walk (no `os.walk` recursion depth risk, no `pathlib.rglob` symlink surprises). Follows dir symlinks? **No by default** (`--follow-symlinks` opt-in, default off). File symlinks: scan target once, report under link path + `real_path` in JSON; loop detection via `(st_dev, st_ino)` visited set.
- **Hidden files:** included by default (`.env` is hidden-ish and critical) EXCEPT `.git/` dir (always excluded, no flag to include in MVP).
- **Symlinks:** as above; broken symlink → counted `files_errored`, continue.
- **Binary detection:** first 8 KiB contains `\x00` → `skipped_binary`. Also skip known binary extensions pre-read (see §18) to avoid wasted I/O.
- **Encoding:** try `utf-8-sig` → `utf-8` with `errors=replace`; never crash on `UnicodeDecodeError`; replace char `U+FFFD` counted; lines split on universal newlines. `utf-16` BOM? Detect BOM bytes and decode accordingly (small explicit BOM table), else replace-mode.
- **Large files:** `stat.st_size > max_file_bytes` (default 5 MiB, config `[scan] max_file_bytes`) → skip with `skipped_oversize` (still counted). Files under limit but with a line > `max_line_len` (default 100 KiB) → truncate line, set `truncated:true`, continue.
- **Permission errors:** `OSError` on open/stat → `files_errored`, warning on stderr, continue. Never traceback in default mode; traceback only with `--verbose` (still redacted).
- **Generated/vendor/minified:** detected by path/extension + content heuristics (§16.8); not skipped outright (signatures still run - `.npmrc` in a vendored dir can hold a real token) but generic entropy gated.
- **Lockfiles:** scanned by signatures only (entropy path disabled) to control noise/perf.
- **Concurrency (MVP): none.** Sequential loop. Rationale: I/O-bound but regex-bound in practice; threading adds nondeterminism risk for marginal gain at MVP scale. Revisit in v1.0 behind `--jobs N` only if benchmarks (§35) show > 2× win on 10k-file corpus.

Per-file budget enforcement: open → gate → stream lines → per-line candidate cap (default 20 candidates/line) → per-file candidate cap (500) → per-file finding cap (100). Caps counted in stats.

---

## 18. File-Type Strategy

MVP is **content-driven, not parser-driven**: line regexes work on any text file. File type only modulates context and gates.

| Category | Extensions / names | Treatment |
|----------|-------------------|-----------|
| Python | `*.py` | Full pipeline; `# secretsieve:ignore` honored; triple-quoted strings scanned line-wise |
| JS/TS | `*.js *.jsx *.ts *.tsx *.mjs *.cjs` | Full pipeline; `*.min.js *.bundle.js` → generated mode |
| JSON | `*.json` | Key-context extraction (`"password": "..."`); `.map` files → generated mode |
| YAML | `*.yml *.yaml` | Key-context (`password: ...`); no full YAML parse in MVP |
| TOML | `*.toml` | Key-context (`password = ...`) |
| dotenv | `*.env*`, `.env*`, `*.env.example` | Primary target; `KEY=value` unquoted capture; `.example` capped INFO |
| Shell | `*.sh *.bash *.zsh`, `Dockerfile*`, `*.dockerfile` | `export`/`ENV`/`ARG` context; Dockerfile secrets flagged HIGH |
| Config/text | `*.ini *.cfg *.conf *.properties *.xml *.html *.md *.txt` | Scanned; `.md` docs-demotion applies |
| Keys/certs | `*.pem *.key *.rsa *id_rsa* *.p12 *.pfx` | Filename boost; binary-safe gate (DER `*.p12` is binary → skipped_binary, but name still surfaced in `--verbose` as note, never a finding without content) |
| Explicitly skipped (pre-read) | images/video/fonts/archives/executables: `*.png *.jpg *.gif *.webp *.mp4 *.woff2 *.zip *.tar.gz *.exe *.dll *.so *.dylib` + `assets/icon.webp` (project's own icon - binary, never scanned for secrets) | Counted `skipped_extension` |

Future file-type expansion: adding an entry = one row in `scanner/filetypes.py` (`extensions`, `content_gates`, `context_boost`, `entropy_mode`) + tests. No engine change.

---

## 19. Ignore / Exclusion Strategy

Layered, deterministic, precedence highest-last:

1. **Hard-coded always-excluded dirs (cannot be overridden in MVP):** `.git/` (history scanning is future; working-tree scan never descends into `.git`). Rationale: prevents accidental history dump + perf cliff.
2. **Default excluded dirs (overridable with `--no-default-excludes` or config):** `node_modules/`, `dist/`, `build/`, `out/`, `.venv/`, `venv/`, `__pycache__/`, `.tox/`, `.mypy_cache/`, `.pytest_cache/`, `vendor/`, `target/`, `.idea/`, `.vscode/` (config dirs, not code - low yield). Note: these are still scannable when passed EXPLICITLY as a path arg (`secretsieve node_modules/foo.js` scans it) - exclusion applies to recursive descent, not explicit args. This prevents "blindly missing the config you pointed at."
3. **Default excluded files:** `package-lock.json` entropy-gated (not fully excluded), `*.min.js` entropy-gated, `*.map` entropy-gated. True excludes: `*.lock`? No - lockfiles scanned signature-only. True binary extensions (§18) skipped.
4. **User `--exclude` / `--include` globs:** gitignore-style `fnmatch` + `**` support via `pathlib.PurePath.match`; `--exclude` appends to defaults; `--include` is an allowlist that, if present, restricts to matches (after excludes). Multiple flags repeatable. CLI beats config; explicit path arg beats `--include` miss (with warning).
5. **Config `[scan] exclude/include`:** same syntax, loaded from `secretsieve.toml`.
6. **Inline `# secretsieve:ignore`:** line-level only (§16.7).

Do NOT exclude useful config: `.env` (except `.env.example` demotion), `docker-compose.yml`, `Dockerfile`, `settings.py`, `config/*`, `*.pem`, `credentials.json` are NEVER in defaults.

`.gitignore` honoring? **No in MVP** (explicit non-goal for MVP; future opt-in `--respect-gitignore`). Rationale: security tool must not inherit a project's convenience ignores; secrets in gitignored `.env` are exactly what must be found locally before commit.

---

## 20. Finding Data Model

Immutable dataclass (`models/finding.py`), constructed ONCE with redaction applied. No raw secret stored on the object.

```python
# Conceptual shape (field names normative for JSON parity, §26)
Finding(
  id="f-a3f9c1…",               # uuid4 hex[:12], unique per run (not stable)
  fingerprint="sha256:…",       # stable dedup key (§20.1)
  rule_id="SS-GITHUB-001",
  detector="signature",          # signature | entropy | generic
  provider="github",             # aws | github | slack | … | generic
  category="api_token",          # api_token | private_key | db_credential | password | connection_string | webhook_secret | bearer | jwt | env_secret
  severity="CRITICAL",           # CRITICAL|HIGH|MEDIUM|LOW|INFO
  confidence=98,                 # 0-99 int
  confidence_band="very-high",
  path="config/aws.py",          # relative to scan root, posix-style
  line=18, column=12,            # 1-indexed; column = start of VALUE span
  end_column=52,                 # where supported, else null
  redacted="AKIA****************9X2F",  # preview only (§25 redaction spec)
  value_hash="sha256:…",         # hash of RAW value for cross-run correlation WITHOUT storing value
  reason="provider signature + credential context",
  reason_codes=["prefix_match","validator_pass","strong_context"],
  context_key="api_key",         # normalized assignment key or null
  generated=False, truncated=False,
  suppressed=False,
)
```

### 20.1 Fingerprint (normative)

`fingerprint = "sha256:" + sha256(f"{rule_id}\x00{norm_path}\x00{line}\x00{col}\x00{value_hash}").hexdigest()[:32]`

where `norm_path` = posix relative path lowercase on Windows, `value_hash = sha256(raw_value.encode()).hexdigest()`. Properties: stable across runs for same content/location; moves with the secret (line change → new fingerprint, expected); does not reveal the secret; suitable for `[[allow.fingerprint]]`.

### 20.2 Ordering (normative)

Sort key: `(severity_rank, -confidence, path, line, column, rule_id)` with `CRITICAL=0..INFO=4`. Guarantees deterministic output for CI diffing.

---

## 21. Rule System

### 21.1 Rule object (normative fields)

```python
# Conceptual shape
Rule(
  id="SS-GITHUB-001", name="GitHub personal access token",
  provider="github", category="api_token", severity="CRITICAL",
  base_confidence=90,
  pattern=<compiled regex>,          # precompiled, ASCII where possible
  validator="jwt_structure",         # optional callable name or None
  context_required=False,            # True for generic/AWS-secret rules
  entropy_profile="base64",          # base64|hex|mixed|none - selects §11 thresholds for generic path
  keywords=("github","ghp","gho"),   # context boost hints
  description="…", remediation="Revoke at github.com/settings/tokens…",
  fp_notes="Docs examples containing EXAMPLE are suppressed…",
  version=1,
)
```

### 21.2 Storage: Python modules (decision + rationale)

**Decision: rules are Python modules** in `rules/` (one file per provider/family, e.g. `rules/aws.py`, `rules/github.py`, `rules/generic.py`), each exporting a `RULES: list[Rule]`, auto-registered via explicit `rules/__init__.py` import list (no filesystem auto-import magic - explicit is auditable and avoids importing stray files).

Rejected alternatives: YAML/JSON rule files (would need a mini-engine + sandbox for validators; regex-only YAML can't express JWT decode/DB parse; escaping hell; still needs code review per rule - so keep rules as reviewed code), database/dynamic feed (network + trust problem).

Custom rules (§29) use a restricted TOML shape compiled into the same `Rule` type - the ONLY non-Python rule path, deliberately less expressive (regex + thresholds, no arbitrary validators).

### 21.3 Lifecycle

Add rule = create/clone module entry + positive/negative fixtures + docs row + `rules list` output update. Disable rule = config `rules.disabled = ["SS-DISCORD-001"]` or `--disable-rule` flag (repeatable). No rule deletion without major version + changelog (stable IDs, §22).

---

## 22. Rule ID Strategy

Format: `SS-<FAMILY>-<NNN>` where `SS` = SecretSieve fixed prefix, `FAMILY` = uppercase provider/category token, `NNN` = zero-padded sequence starting 001 per family.

- Examples: `SS-AWS-001`, `SS-AWS-002`, `SS-GITHUB-001`, `SS-SLACK-001`, `SS-STRIPE-001`, `SS-DISCORD-001`, `SS-JWT-001`, `SS-PRIVATE-KEY-001` (family token may contain hyphens for readability; canonical form uses hyphens, e.g. `SS-PRIVATE-KEY-001`), `SS-DB-001`, `SS-GENERIC-001`, `SS-ENV-001`.
- Stability: IDs are permanent. Semantics may tighten (fewer FPs) in minor versions; loosening (more hits) requires minor + changelog; ID reuse is forbidden.
- Custom rules: MUST use `SS-CUSTOM-<NNN>` or `SS-<ORG>-<NNN>` with `custom:true` marker and are namespaced separately to avoid collision with built-ins; loader rejects IDs matching built-in families unless `custom:true` + distinct family token.
- CLI `explain` accepts any built-in ID and prints full rule card (pattern essence - never a weaponized copy-paste bypass guide - plus severity rationale, examples of redacted hits, FP notes).

---

## 23. CLI Architecture

Stdlib `argparse` front end (`cli/parser.py` builds parser, `cli/app.py` runs scan controller, `cli/output.py` renders). No Click/Typer/Rich in MVP (§37 rationale).

Layers:

```
argv → parser (validate, mutual-exclusion) → config loader (merge CLI > config file > defaults)
     → scan controller (progress + stats) → engine → findings → reporter (human|json)
     → exit code (§27)
```

Config resolution: `--config PATH` explicit > `./secretsieve.toml` > `./pyproject.toml [tool.secretsieve]` > defaults. `--no-config` ignores files (CI hermeticity). Unknown config keys = hard error (fail closed, exit 2) to catch typos.

TTY behavior: color enabled iff stdout is TTY AND `--no-color` absent AND `NO_COLOR` env unset AND `TERM != dumb`. `--json` implies no color, no progress, single JSON document on stdout; warnings/errors on stderr.

---

## 24. CLI Commands

Decision: **implicit-scan single command + three read-only helpers.** No deep `git`-style subcommand tree in MVP (keeps `secretsieve .` frictionless while giving explicitness for CI).

```
secretsieve [PATH ...] [options]          # implicit scan (default PATH = .)
secretsieve scan [PATH ...] [options]     # explicit scan, identical behavior (CI clarity)
secretsieve rules [--list | --show SS-XXX-NNN]
secretsieve explain SS-XXX-NNN            # alias of rules --show, human-friendly name
secretsieve config [--init | --validate]  # --init writes template toml; --validate checks it
```

Normative options (MVP - deliberately small; every flag justified):

| Flag | Purpose | Default |
|------|---------|---------|
| `--json` | Machine-readable output (§26) | off |
| `--quiet` / `-q` | Findings only (failures + findings; progress + summary suppressed; human mode prints one line per finding) | off |
| `--verbose` / `-v` | Debug detail WITHOUT secrets: stats, suppress counts, per-file skips, timing | off |
| `--no-color` | Disable ANSI | auto-detect |
| `--severity LEVEL` | Minimum DISPLAY severity (`low` default; `info` shows INFO) | `low` |
| `--fail-on LEVEL` | Minimum severity that triggers exit 1 (`high` default? - decision: default `low`, i.e. any LOW+ fails; INFO never fails) - see §27 | `low` |
| `--min-confidence N` | Hide findings below N (0–99) | 0 (show all) |
| `--exclude GLOB` (repeatable) | Extra exclude | - |
| `--include GLOB` (repeatable) | Restrict to matches | - |
| `--no-default-excludes` | Drop default dir excludes | off |
| `--config PATH` / `--no-config` | Config source control | auto-discover |
| `--disable-rule ID` (repeatable) | Rule kill-switch | - |
| `--max-file-bytes N` | Override size gate | 5 MiB |
| `--output PATH` | Write JSON report to file (with `--json`) instead of stdout | stdout |

Deliberately deferred (NOT in MVP): `--follow-symlinks` (design done, flag ships v1.0), `--jobs`, `--respect-gitignore`, `--strict` (fail on any inline-ignore), `--sarif`, `--only-rule`, `--stdin` pipe mode. Each deferred flag is listed in `--help` epilog as "planned" ONLY if implementation tracks it - otherwise omitted to avoid vaporware.

Examples:

```bash
secretsieve .                              # human scan of cwd
secretsieve ./src config.py --severity high
secretsieve scan . --json --fail-on high > report.json
secretsieve scan . --quiet --fail-on critical
secretsieve rules --list
secretsieve explain SS-GITHUB-001
secretsieve config --init > secretsieve.toml
```

---

## 25. CLI UX

### 25.1 Human output (normative layout)

```
SecretSieve v0.1.0 - scan .

Files scanned:        428
Files skipped:         31  (12 binary, 14 excluded, 5 oversize)
Candidates evaluated: 1_204
Findings:               7  (2 critical, 3 high, 2 medium)

CRITICAL  AWS Secret Access Key - config/aws.py:18  [SS-AWS-002 · conf 98% · very-high]
  AKIA****************9X2F
  Reason: provider signature + credential context (aws_secret_access_key)

HIGH  GitHub Token - .env:12  [SS-GITHUB-001 · conf 96% · very-high]
  ghp_********************
  Reason: prefix signature + env context

Summary: 7 findings (2 critical · 3 high · 2 medium) in 0.42s - exit 1
```

Rules: header (tool + version + target), stats block, findings sorted (§20.2), one block per finding (severity color chip + title + location + rule/conf + redacted preview + reason), summary footer with timing + exit code. `--quiet` collapses each finding to `SEVERITY path:line rule_id conf%`. `--verbose` appends suppress/skip accounting and per-engine timing. No ASCII-art banners, no spinners that break CI piping, no hacker clichés.

Severity colors (only when color enabled): CRITICAL bright-red, HIGH red, MEDIUM yellow, LOW cyan, INFO gray. Never color the redacted value itself (avoids leaking length via styling bugs - plain text always).

### 25.2 Redaction (mandatory, normative)

- Default preview: **first 4 chars + `*` mask + last 4 chars**, e.g. `AKIA****************9X2F`, `ghp_********************` (short values: first 2 + last 2). Mask length fixed at 16 stars regardless of true length (hides true length). Values ≤ 8 chars: `********` fully masked.
- PEM blocks: show `-----BEGIN RSA PRIVATE KEY----- [redacted 1679 bytes]` - never key body.
- DB URLs: `postgres://app:********@db.internal:5432/app` - redact password segment only.
- JSON output: `redacted` + `value_hash` only. Raw value field MUST NOT exist in the schema. `--verbose`/debug MUST NOT add raw values. Exceptions/log lines MUST sanitize `'`-quoted candidates via central `redact()` helper - direct `print(value)` of a candidate is a security bug and a test failure (static test asserts no `print(.*value` in reporters).
- Terminal escape safety: all file paths, key names, reasons passed through `sanitize_for_terminal()` (strip C0/C1 controls, ANSI CSI) before render (§32).

---

## 26. Output Formats

### 26.1 Human-readable terminal (§25.1)

### 26.2 JSON (normative schema v1)

Top-level object; `findings` array sorted (§20.2); `stats` for audit; `config_snapshot` (resolved thresholds, NOT secrets) for reproducibility.

```json
{
  "tool": "secretsieve",
  "version": "0.1.0",
  "schema_version": 1,
  "scan_root": ".",
  "started_at": "2026-10-07T00:00:00Z",
  "duration_ms": 420,
  "stats": {
    "files_scanned": 428, "files_skipped": 31,
    "skip_breakdown": {"binary": 12, "excluded": 14, "oversize": 5},
    "files_errored": 0, "candidates": 1204,
    "suppressed": {"placeholder": 41, "hash_or_uuid": 18, "test_fixture": 6},
    "truncated_files": 0
  },
  "findings": [
    {
      "id": "f-a3f9c1e2b4d6",
      "fingerprint": "sha256:9f2c…",
      "rule_id": "SS-AWS-002",
      "detector": "signature",
      "provider": "aws",
      "category": "api_token",
      "severity": "CRITICAL",
      "confidence": 98,
      "confidence_band": "very-high",
      "path": "config/aws.py",
      "line": 18, "column": 12, "end_column": 52,
      "redacted": "AKIA****************9X2F",
      "value_hash": "sha256:…",
      "reason": "provider signature + credential context",
      "reason_codes": ["prefix_match", "strong_context"],
      "context_key": "aws_secret_access_key",
      "generated": false, "truncated": false
    }
  ],
  "config_snapshot": {"severity_floor": "low", "fail_on": "low", "min_confidence": 0, "max_file_bytes": 5242880},
  "exit_code": 1
}
```

Schema guarantees: additive-only changes within major version (new optional fields OK; renaming/removing = major bump). `schema_version` integer increments on any breaking change. A JSON-schema file (`schemas/report-v1.json`) ships in v1.0 and is validated in tests; MVP locks field names above so v1.0 schema is non-breaking. SARIF is future (maps 1:1 from this schema).

---

## 27. Exit Codes

Normative (generic-CI friendly, no custom integrations needed):

| Code | Meaning | Condition |
|------|---------|-----------|
| `0` | Clean | No findings at or above `--fail-on` AND no fatal errors |
| `1` | Findings | ≥1 finding at or above `--fail-on` severity (regardless of non-fatal file errors; errors still reported) |
| `2` | Operational error | Bad path/config/flag, unreadable config, no scannable files, fatal I/O; OR no qualifying findings BUT `files_errored > 0` |

Determinism: same tree + same flags + same version → same code. `--fail-on` levels: `critical > high > medium > low` (INFO never triggers 1). Default `--fail-on low` (any LOW+ fails; INFO ignored). `--severity` controls DISPLAY only and never affects the exit code except that suppressed-from-display findings still count for `fail-on` (prevents hiding failures with display filters - documented prominently).

CI examples:

```bash
secretsieve scan . --json --fail-on high > report.json; echo $?   # gate on HIGH+
secretsieve scan . --quiet --fail-on critical                    # block only on CRITICAL
```

---

## 28. Configuration System

File: `secretsieve.toml` (preferred) or `[tool.secretsieve]` in `pyproject.toml`. Parsed with stdlib `tomllib` (3.11+); `tomli` fallback shim for 3.9–3.10 if supported range requires it (decided in Phase 1: minimum Python = 3.9 or 3.10 - recommendation: **3.10+** for `match`-free clean typing + `tomllib` backport simplicity).

Normative template (`config --init` emits this with comments):

```toml
[scan]
# Globs relative to scan root. CLI --exclude/--include append to these.
exclude = ["node_modules/**", "dist/**"]
include = []
follow_symlinks = false
max_file_bytes = 5242880
max_line_len = 102400
respect_gitignore = false  # reserved future; setting true in MVP warns + ignored

[output]
format = "human"        # human | json
severity_floor = "low"  # info|low|medium|high|critical
fail_on = "low"
min_confidence = 0
no_color = false

[entropy]
# Overrides for §11 thresholds; all optional.
base64_threshold = 4.5
hex_threshold = 3.7
mixed_threshold = 4.0
min_length = 16

[rules]
disabled = []           # e.g. ["SS-DISCORD-001"]

[allow]
placeholder_values = [] # extra case-insensitive dummy values for this org
# [[allow.fingerprint]] r"""sha256:…"""  # stable suppressions (§16.7)
# [[allow.path_rule]] { rule = "SS-GENERIC-001", path = "tests/fixtures/**" }

[advanced]
max_candidates_per_file = 500
max_findings_per_file = 100
```

Rules: unknown key = error exit 2 (typo safety); all paths validated (no `..` escapes required - globs are matched, not opened); `--validate` checks schema + glob compilability + rule-ID existence; config errors print file:line-ish TOML error + hint, never traceback by default. No code execution from config (no `eval`, no plugin paths in MVP).

---

## 29. Custom Rules

**Status: future (post-v1.0), designed now so MVP types don't block it.**

Proposed TOML shape (one `[[custom_rule]]` per rule, loaded from `secretsieve.toml` or `--custom-rules PATH`):

```toml
[[custom_rule]]
id = "SS-CUSTOM-001"
name = "Internal deploy token"
provider = "acme"            # lowercase alnum, used for docs grouping
category = "api_token"
severity = "HIGH"            # enum-gated
pattern = "acme_[A-Za-z0-9]{24,}"   # regex, length-bounded, ReDoS-checked at load
context_required = true
keywords = ["acme", "deploy_token"]
entropy_profile = "mixed"
confidence_boost = 10        # capped; total still clamped 0-99
description = "…"
remediation = "Rotate in Acme dashboard → Settings → Tokens."
```

Safe loading (normative for future implementation): IDs must match `^SS-[A-Z0-9-]+-[0-9]{3}$` and not collide with built-ins; `severity`/`category` enum-validated; `pattern` compiled with timeout guard + static ReDoS heuristics (reject nested quantifiers `(a+)+`, unbounded `.*.*`, lookbehind of variable length); compile failure = config error exit 2 naming the rule; no validators/validators-as-code in custom path (regex + context + entropy only); max 50 custom rules, max pattern length 500 chars. Error handling: per-rule try/except at load; one bad rule fails the whole run (fail closed - partial rule sets give false confidence).

---

## 30. Git Integration

Explicitly **layered and deferred**. MVP scans the working tree as plain files (`.git/` excluded). Architecture MUST NOT entangle scanning with Git so history support is additive.

| Layer | Content | Milestone |
|-------|---------|-----------|
| L0 working tree (MVP) | Plain recursive scan; no Git dependency; works in tarballs/CI checkouts without `.git` | MVP |
| L1 staged/unstaged file lists (v1.0 candidate) | Optional `secretsieve scan --staged` / `--unstaged` resolving `git diff --name-only` to path list, then reusing the same file pipeline; Git binary optional (absent → clean error) | v1.0 |
| L2 commit range (future) | `git show` per blob → in-memory scan (never checkout); per-commit finding attribution | Future |
| L3 history (future) | `git log -p` streaming with commit/author/date attribution + "introduced in" reporting; large-repo paging + time bounds | Future |

Design constraints for later layers: operate on blob bytes in memory (no temp checkouts), bound history depth by default (`--max-commits`), attribute findings with `commit`, `author`, `date` extra fields (additive JSON fields), and document that history scanning surfaces already-rotated secrets (remediation = rotation + history rewrite guidance, not just deletion).

---

## 31. Performance Architecture

Principles: measure first, stream everything, compile once, gate early, no speculative concurrency.

1. **Streaming:** files read line-by-line (`io.open(..., errors="replace")` iterator); never `read()` a whole file into memory (except PEM block lookahead bounded at 16 KB). Memory per file O(longest line cap), not O(file size).
2. **Stat-first gating:** `st_size` checked before open (oversize/binary-extension skips cost one stat).
3. **Compiled patterns:** all rule regexes compiled at import; combined alternation where safe (single pass for cheap prefilter `SECRET_PREFILTER = re.compile(r"(AKIA|ghp_|gho_|xox.|sk_(live|test)|-----BEGIN|eyJ|bearer|password|secret|api[_-]?key|token)", re.I)`) - lines failing prefilter skip expensive rules (except `.env`/PEM-filename-boosted files which run full set). Prefilter MUST be validated to never exclude a Tier-1 true positive (test: every positive fixture matches prefilter).
4. **Candidate-scoped entropy:** entropy runs on ≤512-char candidates only; histogram over 256 bins in pure Python loop is fast enough at this scale (benchmarked in Phase 4; C-extension explicitly rejected).
5. **Allocation discipline:** reuse compiled objects, avoid per-line dict building until a candidate exists, intern reason-code strings.
6. **Concurrency policy:** MVP sequential. v1.0 `--jobs N` (ThreadPool, files in parallel, deterministic merge-sort after) ONLY if §35 benchmarks on a 10k-file synthetic corpus show ≥2× wall-clock win with identical findings. No multiprocessing (pickle + Windows spawn cost unjustified), no async (no I/O multiplexing benefit for local walk + regex CPU mix).
7. **Worst-case bounds:** adversarial single 5 MB one-line file → truncated-line path, completes in bounded time; 100k-file tree → stat-gated walk, progress via `--verbose` heartbeat (no spinner). Benchmarks MUST include these adversarial cases.

---

## 32. Security of SecretSieve

The scanner routinely handles attacker-controlled content. Normative hardening list (each item needs a test in §34):

1. **Malicious filenames:** never interpolate paths into shell (no `shell=True` anywhere - static test); render via `sanitize_for_terminal()`; JSON-escape via `json` module only; handle `\n`, `\r`, `\x1b`, RTL overrides, 4 KB names, Windows reserved names, trailing dots.
2. **Unicode weirdness:** operate on decoded `str` with `errors=replace`; normalize key lookup with `.casefold()`; Tokenizer splits on Unicode word boundaries safely; homoglyphs need no special handling (signatures are ASCII-anchored; non-ASCII values go through generic path with `non_ascii` class flag, never crash).
3. **Encoding attacks:** BOM table explicit (`utf-8-sig`, `utf-16-le/be` via BOM only); no `chardet` dependency (attack surface + nondeterminism); overlong/mixed encodings degrade to `U+FFFD`, never raise.
4. **Terminal escape injection:** `sanitize_for_terminal()` strips `\x00-\x1f\x7f-\x9f` except `\t`, removes CSI/OSC sequences (`\x1b[...`, `\x1b]...`), truncates fields to 500 chars for display. Finding reasons/paths/keys all pass through it. Test with `$(printf '\x1b[2J...')` filenames.
5. **JSON injection:** only `json.dump(s)`; never hand-built JSON strings; `ensure_ascii=True` default to neutralize control chars; no raw values in schema (§25.2).
6. **Path traversal assumptions:** scan root resolved via `Path.resolve()`; reported `path` always relative (fallback to absolute + warning if outside root, e.g. symlink target); config globs matched, never opened; `--output` path must not escape via `..` silently - resolve + warn.
7. **Symlink abuse:** default no dir-symlink follow; visited `(st_dev, st_ino)` set prevents loops; file symlink reported under link path with `real_path`; TOCTOU accepted (scanner is point-in-time; document it).
8. **ReDoS / catastrophic backtracking:** pattern review rules - no `(x+)+`, no `.*.*` chains, all repetitions bounded (`{m,n}` with n ≤ 512), alternations ordered longest-prefix-first, `re` only (no `regex` backtracking extensions). Load-time self-test: each pattern matched against 10 KB adversarial input (`"a"*10000 + "!"`) with per-pattern 100 ms budget in CI (fails the build if exceeded).
9. **Resource exhaustion:** `max_file_bytes`, `max_line_len`, per-file candidate/finding caps, total `--max-findings` (default 10_000, excess truncated with notice); no recursion (iterative walk); no unbounded PEM lookahead.
10. **Malicious config:** `tomllib` only; size-cap config file at 1 MB; unknown keys = error; regexes from custom rules length- and complexity-gated (§29); no include-directives (no file inclusion from config in MVP).
11. **Log injection:** stderr warnings single-line sanitized; `--verbose` timing never includes content; tracebacks (only under `--verbose` + `PYTHONBREAKPOINT` unset) scrubbed of candidate values by exception-formatter wrapper.

---

## 33. Testing Strategy

All test secrets MUST be fake/non-sensitive: synthetic values matching formats but drawn from reserved/example spaces (`EXAMPLE`, `0000…`, `test_…`), plus a `tests/README` + pre-commit grep asserting no live-looking `sk_live`/`ghp_` with high entropy outside fixtures, and a documented "if you accidentally commit a real secret to this repo, rotate immediately" policy. Fixtures live under `tests/fixtures/` mirroring §20 ordering.

| Suite | Location (planned) | Content & gates |
|-------|-------------------|-----------------|
| Unit - signatures | `tests/unit/test_rules_*.py` | Per-rule positive (≥5) + negative (≥10 incl. placeholders, hashes, docs prose) fixtures; pattern ReDoS budget test |
| Unit - entropy | `tests/unit/test_entropy.py` | Hand-computed Shannon vectors (`"aaaa"` H=0, `"ab"` H=1.0, known base64 strings ±0.05), threshold-boundary tests, encoding-guess tests |
| Unit - context | `tests/unit/test_context.py` | `monkey`≠`key` tokenization, `API_KEY` vs `keyboard`, benign-file demotion, `.env.example` cap |
| Unit - confidence/severity | `tests/unit/test_scoring.py` | Locked worked examples from §14.4; severity-never-from-confidence property test |
| Unit - redaction | `tests/unit/test_redact.py` | Fixed-mask lengths, short-value full mask, PEM/DB-URL cases, property: raw value ∉ rendered output |
| Integration - scanner | `tests/integration/test_scan_tree.py` | Synthetic repo (py/js/json/yaml/env/Dockerfile + binary + symlink + oversize + minified + lockfile) asserting exact finding set + stats + ordering |
| CLI | `tests/cli/test_cli.py` | Exit codes 0/1/2 matrix, `--fail-on`/`--severity`/`--min-confidence`/`--quiet`/`--json`/`--no-color`/`--disable-rule`/`--config` behaviors; golden human + JSON snapshots (schema field-name lock) |
| FP regression | `tests/regression/test_fp_corpus.py` | Curated FP corpus (UUIDs, hashes, webpack chunks, docs, fixtures) - MUST yield zero findings above LOW; new FPs added as fixtures with the fix |
| Config | `tests/unit/test_config.py` | Template validity, unknown-key rejection, glob compile errors, bad rule-ID errors |
| FS edge cases | `tests/integration/test_fs_edges.py` | Deep nesting (30+), permission-denied (skip on Windows CI if needed), broken symlink, BOM/UTF-16 files, 1 MB single-line file, non-UTF8 bytes, empty tree |
| Determinism | `tests/unit/test_determinism.py` | Same tree scanned twice + shuffled `os.scandir` order mock → byte-identical JSON findings order |
| Privacy/offline | `tests/unit/test_privacy.py` | Scan with sockets blocked (`socket.socket` patched to raise) → success; static import audit for network modules in scan path |

Coverage target: ≥90% lines on `scanner/`, `detectors/`, `analyzers/`, `models/` (enforced in CI-generic `pytest --cov` gate - informational in MVP, required in v1.0). Every rule ships with its fixtures or it does not ship.

Test corpus strategy (checked in, all synthetic): `positive/` (per-rule true hits), `negative/` (placeholders, hashes, UUIDs, prose), `edge/` (encodings, minified, lockfiles, huge lines, malformed TOML/JSON/YAML that must not crash the line scanner), `multilang/` (py/js/ts/json/yaml/toml/sh/Dockerfile/env samples with equivalent secrets).

---

## 34. Security Testing

Dedicated suite beyond functional tests (maps 1:1 to §32):

- **Escape-injection tests:** filenames/keys containing ANSI CSI, OSC hyperlinks, `\r` overwrite, RTL override → assert rendered stdout contains no `\x1b` and JSON round-trips.
- **ReDoS budget tests:** per-pattern adversarial timing (§32.8); whole-scan timeout on 5 MB single-line + 10k-file synthetic tree (CI timeout guard, not a perf promise).
- **Redaction audit:** property test - for every fixture finding, `raw_value not in stdout and raw_value not in json_out`; plus `--verbose` output included.
- **Config abuse:** 1 MB+ config, recursive-glob bomb (`**/**/**`), 500-char regex, unknown keys → clean exit 2, no traceback by default.
- **Symlink loop:** cyclic dir symlinks + `--follow-symlinks` (v1.0 flag; MVP asserts default does NOT follow) → terminates, visited-set bounded.
- **Secret-hygiene of the repo itself:** CI-generic step (documented for any CI, not GH-specific): `git diff --cached` scanned by the built tool in a self-check (`secretsieve scan . --fail-on medium` on its own tree must be clean); plus a committed `.secretsieve-allow` story if self-fixtures would trip it (fixtures dir excluded via shipped config example, not inline ignores).

---

## 35. Performance Testing

No fake numbers in this plan. Normative benchmark design (harness ships in v1.0, manual in MVP):

- **Corpora (synthetic, checked-in generator script `tools/gen_perf_corpus.py` - future file, not now):** S (500 files / 5 MB), M (5k files / 80 MB), L (20k files / 400 MB), plus adversarial (one 5 MB single-line file; 10k empty files; deep 50-level nesting).
- **Metrics:** wall time, files/sec, MB/sec, peak RSS (via `resource`/`tracemalloc` sampling), per-stage timing (`--verbose` breakdown: discovery/filtering/regex/entropy/scoring/report), rule cost ranking (slowest 5 rules), entropy cost share.
- **Method:** cold page-cache + warm runs (report median of 5), pinned Python version, `pytest-benchmark`-free (stdlib `time.perf_counter` harness to avoid dependency), results recorded in `docs/PERF.md` (future file) with machine specs - never as marketing claims in README.
- **Regression rule:** L-corpus scan must complete without OOM on 512 MB container; any >20% median regression vs baseline fails the (generic-CI) perf job in v1.0. MVP acceptance: S-corpus "feels instant" (< 2 s target, measured not promised) and M-corpus bounded (< 30 s) on a commodity laptop.

---

## 36. Python Architecture

Minimum version: **3.10+** (decision: `tomllib` via backport shim `tomli` for 3.10, native 3.11+; `X | Y` unions, `match`-avoidant style, `dataclasses` stdlib). Zero runtime dependencies in MVP.

Planned package layout (described only - NOT created in this phase):

```
src/secretsieve/
  __init__.py          # __version__ single source
  __main__.py          # python -m secretsieve entry
  cli/
    parser.py          # argparse definition; pure function build_parser() -> parser (testable w/o I/O)
    app.py             # ScanController: config merge → scanner → reporter → exit code
    output.py          # human + json renderers; sanitize_for_terminal(); redact() re-export
  scanner/
    discovery.py       # iterative scandir walk, symlink policy, visited-inode set
    filters.py         # include/exclude globs, default excludes, extension gates
    gating.py          # binary (NUL sniff), size caps, BOM/encoding detection
    reader.py          # line streaming, truncation flags, line index
    orchestrator.py    # per-file pipeline driver + stats + budgets
  detectors/
    signatures.py      # prefilter + per-rule match loop + validator dispatch
    entropy.py         # Shannon H, encoding guess, thresholds, margin scoring
    context.py         # key tokenization, hint sets, file/dir signals
    heuristics.py      # validators (jwt/db/pem), pair booster, data-uri skip
    fp_filters.py      # placeholder/hash/uuid/generated/allowlist/ignore (ordered gates)
    scoring.py         # confidence formula + severity map + bands
  rules/
    __init__.py        # explicit RULE_REGISTRY list (no magic imports)
    aws.py, github.py, slack.py, stripe.py, discord.py,
    jwt.py, privatekey.py, database.py, generic.py, dotenv.py
  models/
    finding.py         # frozen dataclass Finding + fingerprint() + sort_key()
    rule.py            # frozen dataclass Rule + family/severity enums
    config.py          # Config dataclass + defaults + merge(cli,file,defaults)
    stats.py           # ScanStats counters
  reporting/
    human.py           # layout from §25.1
    json_report.py     # schema v1 builder (§26.2)
  config/
    loader.py          # tomllib/tomli read, unknown-key rejection, --validate
    template.py        # --init template string
  git/
    __init__.py        # STUB in MVP: raises clean "not yet supported" for --staged etc.; L1+ implemented here
  utils/
    redact.py          # redact(), hash_value(), value_hash()
    sanitize.py        # sanitize_for_terminal()
    paths.py           # resolve, rel_posix, glob match helpers
    timing.py          # --verbose stage timers (stdlib only)
```

Per-module contract:

- `scanner/*`: input paths/str → file records; NO detection imports (one-way dependency).
- `detectors/*`: pure functions over `(line, lineno, file_ctx)` → candidate/provisional findings; no I/O, no config I/O (config passed as object).
- `models/*`: frozen dataclasses + validation in `__post_init__`; no I/O.
- `reporting/*`: findings+stats → str; never touches raw values (only `redacted`).
- `cli/*`: only place that touches `sys.argv`/`sys.exit`/stdout.
- `config/*`: only place that touches TOML.

Dependency arrows: `cli → config → scanner → detectors → models → reporting`. `git/` isolated until v1.0. This keeps the MVP reviewable (~3–4k lines total target, not a promise - a budget to fight bloat).

---

## 37. Dependency Strategy

**MVP: zero runtime dependencies (stdlib only).** Justification per category:

| Category | Decision | Rationale |
|----------|----------|-----------|
| CLI framework (Click/Typer) | REJECT for MVP | `argparse` covers the small flag set; avoids version pinning + startup cost; parser is unit-testable without a framework |
| Terminal formatting (Rich) | REJECT for MVP | Manual ANSI (few color codes) is 20 lines; Rich adds startup time, width-detection surprises in CI, and a heavy tree for a security tool that must stay lean |
| Data validation (pydantic) | REJECT | Dataclasses + explicit validators; no compile cost, no network-adjacent code in the trust boundary |
| Git integration (GitPython) | REJECT (MVP has no Git features) | L1+ uses stdlib `subprocess` to `git` binary - no library needed, smaller attack surface |
| Packaging (hatchling) | ACCEPT (build-time only) | PEP 517 backend via `pyproject.toml`; not a runtime dep |
| Testing (pytest) | ACCEPT (dev-only) | Industry standard; `pytest` + stdlib `unittest.mock`; no plugins in MVP (no `pytest-benchmark` - stdlib harness instead) |
| TOML backport (tomli) | CONDITIONAL | Only if 3.10 support ships (3.11+ has `tomllib`); declared as `; python_version < "3.11"` qualified dep, never imported on 3.11+ |

Future (v1.0+) candidates, each requiring a written ADR: `rich` (only if UX research proves need), `pyyaml` (only if full YAML parsing ships - must be `safe_load` only), `sarif` helpers (likely hand-rolled instead). Rule: every new runtime dep needs (a) measured benefit, (b) maintainer-activity check, (c) license compatibility check after license decision (§40), (d) offline-install test (`pip install --no-index` from wheelhouse).

---

## 38. Repository Structure

Planned final tree (described only - nothing below is created in this phase):

```
SecretSieve/
  PLAN.md                  # this blueprint (only file created in planning phase)
  README.md                # future: install, quickstart, privacy, CLI ref pointer
  LICENSE                # future: REQUIRED before public release - decision pending (§40)
  pyproject.toml           # future: build (hatchling), entry point, pytest/cov config
  secretsieve.toml         # future: SHIPPED EXAMPLE config (docs), not auto-loaded from package
  src/secretsieve/         # future: §36 layout
  tests/                   # future: §33 layout (unit|integration|cli|regression + fixtures/)
  schemas/
    report-v1.json         # future (v1.0): JSON Schema for §26.2
  assets/
    icon.webp              # EXISTS: official project icon (binary, §39)
  docs/                    # future: architecture, rules-coverage, config, fp-guide, privacy, contributing, perf
  tools/
    gen_perf_corpus.py     # future (v1.0): synthetic perf corpus generator
```

Notable non-entries: no `.github/` (per constraint - no Actions designed or shipped), no `Dockerfile` in MVP (reproducibility via `pipx` + pinned Python; container story is future only if demanded), no `requirements.txt` (PEP 621 `pyproject.toml` is the single source).

---

## 39. Branding

- **Name:** SecretSieve (one word, capital S twice). Binary: `secretsieve`. Package: `secretsieve`. Never `secret-sieve`/`Secret Sieve` in code identifiers.
- **Owner:** 3rabDev - https://3rabdev.online. Every user-facing surface (CLI `--version` line, JSON `tool` field, docs footer, package metadata `Author`) carries this attribution.
- **Icon (`assets/icon.webp` - inspected):** minimal monochrome mark - white abstract sieve/funnel-like glyph with a single dot aperture on a solid black square; pixelated/retro-rendered edges, high contrast, no gradients, no color, no text. Assessment: genuinely usable as the official mark because it already matches the required identity (professional, minimal, technical, security-oriented; avoids hacker-cliché green-on-black, hoods, locks).
  - **Approved uses:** README header image, docs site favicon (converted to PNG/ICO at build), PyPI project image, social preview, release notes header.
  - **Explicitly NOT used:** embedded in terminal output (terminals can't render webp; CLI identity is typographic: `SecretSieve vX.Y.Z` wordmark + consistent severity color chips + monochrome rules). A future `--version` ASCII micro-mark (e.g. `(●)`) may echo the dot-aperture motif - typographic homage, not image embedding.
  - **Palette derived from icon:** black `#0A0A0A`, white `#FFFFFF`, gray `#8A8A8A` + one functional accent reserved for severity (amber/red family only in findings; never in logo). No neon green, no purple gradients.
  - **Voice:** terse, factual, security-professional. Finding titles are noun phrases (`GitHub Token`), reasons are evidence phrases (`prefix signature + env context`), never jokes or scare language.
- **Tagline (proposed, non-normative):** *"Sieve the secrets out of your source."*

---

## 40. Copyright

- Copyright holder: **Copyright © 3rabDev - https://3rabdev.online**. This attribution MUST appear in: `PLAN.md` (done), future `README.md` footer, CLI `--version` output second line, `pyproject.toml` `authors` field, and docs footers.
- **License: NO DECISION HAS BEEN MADE.** The repository currently contains no `LICENSE` file and no license declaration. This plan makes no claim about MIT/Apache/GPL or any other license.
  - **Required action before ANY public release (blocking):** owner selects a license, adds `LICENSE` (+ `pyproject.toml :: license` field), and records the decision + rationale in the release notes. Until then the project is **all rights reserved by default** and MUST NOT be published as open source.
  - Implementation tasks (Phase 1/13) include: license-decision checklist (permissive vs copyleft trade-offs for a security tool, contributor-license implications, dependency compatibility re-check after decision), `LICENSE` placement, and SPDX identifier wiring. No code in this plan assumes a license.

---

## 41. MVP Scope

MVP = genuinely useful first release. Version number: `v0.1.0`. Install: `pip install secretsieve`. Inclusion bar: every item below is acceptance-tested or the release does not ship.

**In:**

1. Working-tree file scanner (§17) with default exclusions (§19), size/binary/encoding gates, stats accounting.
2. Tier-1 signature rules only (§10.2, ~14 rules) with validators + prefilter.
3. Shannon entropy analyzer with per-encoding thresholds + context modifiers (§11).
4. Whole-token context analysis (§12) + ordered FP gates incl. placeholder/hash/UUID/generated/test-fixture + config allowlist + single-line `# secretsieve:ignore` (§16).
5. Deterministic confidence (0–99) + bands (§14) and intrinsic severity (§15) with demotion caps.
6. Immutable finding model + stable fingerprints + deterministic ordering (§20).
7. CLI: implicit `scan`, `--json/--quiet/--verbose/--no-color/--severity/--fail-on/--min-confidence/--exclude/--include/--no-default-excludes/--config/--no-config/--disable-rule/--max-file-bytes/--output`, `rules --list/--show`, `explain`, `config --init/--validate` (§24).
8. Human + JSON-v1 outputs with mandatory redaction (§25–26), exit codes 0/1/2 (§27).
9. `secretsieve.toml` (+ `pyproject [tool.secretsieve]`) config with strict unknown-key rejection (§28).
10. Test suites: unit + integration + CLI + FP regression + determinism + privacy/offline (§33 core rows) at ≥80% coverage of scan/detect paths.
11. Self-scan clean + docs skeleton content defined (not files created - §48 docs list).

**Out (explicitly deferred):** custom rules (§29), Git staged/history (§30 L1–L3), `--jobs` parallelism, SARIF, full YAML parse, `--respect-gitignore`, `--strict`, container image, update checks, telemetry (never), verification calls (never).

---

## 42. v1.0 Scope

v1.0 = polished, production-ready, CI-trusted. Version: `v1.0.0`. Delta on top of MVP:

1. Tier-2 provider rules (Google/GCP/Azure/GitLab/npm/PyPI/OpenAI-disambiguated/SendGrid/Twilio/Dockerfile/shell-export) with per-rule precision measured on corpus (any rule < 90% precision on labeled corpus ships disabled-by-default with docs note).
2. Entropy threshold tuning lock (grid search report in `docs/`), plus `schemas/report-v1.json` + validator in tests.
3. L1 Git file-list mode (`--staged/--unstaged`) reusing the file pipeline; `--follow-symlinks` flag; `--respect-gitignore` opt-in.
4. `--jobs N` iff benchmarks justify (§31.6); perf harness + `docs/PERF.md` numbers (S/M/L + adversarial).
5. `pyproject.toml` packaging hardening: entry-point, `pipx` verified, `python -m secretsieve` parity, wheel install offline test.
6. Docs complete (README + all §48 entries), `--help` polished, `explain` coverage for every rule, FP/ignore guide with security notes.
7. Coverage ≥90% on scan/detect paths; ReDoS budget + redaction property tests in the default suite; self-scan gate documented for any CI.
8. Semver + changelog discipline started; threshold/rule-loosening changes flagged as minor with migration notes.

---

## 43. Future Roadmap

Post-v1.0, strictly prioritized (no commitment dates in this plan):

1. **Custom rules (TOML)** per §29 + `rules --validate-custom` helper.
2. **Git history (L2/L3):** commit-range + history scan with `commit/author/date` attribution + rotation guidance docs.
3. **SARIF output** (`--sarif`) mapped from JSON-v1 for generic code-scanning ingestion (no Actions-specific work).
4. **Paired-secret correlation v2:** cross-file provider pairing (e.g. `user` in YAML + `password` in env with same service prefix) with `related_to` graph in JSON.
5. **Baseline/suppression workflow:** `secretsieve baseline --write baseline.json` + `scan --baseline` (only-new-findings gating for legacy repos) - designed to use fingerprints (§20.1), never raw values.
6. **Pre-commit story (docs only):** generic hook snippet consuming exit codes (no framework-specific product).
7. Optional: `--strict` (fail on any inline-ignore), `--only-rule`, `--stdin` file-list mode, LSP/IDE docs, container image, signed releases (cosign/sigstore evaluation).

Anti-roadmap (will not build without an ADR + owner sign-off): network verification, telemetry, auto-fix, ML models, daemon/watcher, SaaS backend.

---

## 44. Development Phases

Each phase lists Goal, Why, Tasks, Architectural impact, Files/modules affected (future paths), Dependencies, Testing, Acceptance criteria / Definition of done, Risks. Phases are sequential except where noted; no phase starts with the previous phase's acceptance failing.

### Phase 0 - Repository and environment analysis ✅ (this plan)

- **Goal:** establish ground truth (greenfield + `assets/icon.webp` only, no license/code) and freeze the blueprint.
- **Why:** prevents building on false assumptions about existing code.
- **Tasks:** inspect tree, view icon, record state, write `PLAN.md` only.
- **Impact/files:** `PLAN.md` created; nothing else touched.
- **Dependencies:** none.
- **Testing:** verify no files besides `PLAN.md` + `assets/` changed.
- **Done:** `PLAN.md` covers all 48 required sections with normative decisions.
- **Risks:** scope creep into implementation - mitigated by absolute single-file restriction.

### Phase 1 - Project foundation

- **Goal:** installable skeleton: packaging, entry point, versioning, lint/test harness, strict config loader.
- **Why:** every later phase needs `pip install -e .` + `pytest` + `secretsieve --version` working.
- **Tasks:** `pyproject.toml` (hatchling, entry `secretsieve=secretsieve.cli.app:main`, `python>=3.10`), `src/secretsieve/__init__.__version__`, `__main__.py`, `cli/parser.py` (all §24 flags, no engine yet - scan prints "not implemented" exit 2), `models/config.py`, `config/loader.py + template.py`, license-decision checklist opened (§40).
- **Impact:** establishes CLI→config contract; all later modules plug behind it.
- **Files:** `pyproject.toml`, `src/secretsieve/{__init__,__main__,cli/parser,models/config,config/*}`, `tests/unit/test_config.py`, `secretsieve.toml` example content (as test fixture first).
- **Dependencies:** none runtime; dev `pytest`; conditional `tomli`.
- **Testing:** parser matrix (every flag), config merge precedence, unknown-key exit-2, `--init/--validate` round-trip.
- **Done:** `pip install -e .` works; `secretsieve --help/config --validate` exit 0/2 correctly; no network imports.
- **Risks:** Python floor dispute (3.9 vs 3.10) - decide now, document, pin CI matrix accordingly.

### Phase 2 - Scanner engine

- **Goal:** correct, bounded file discovery → filtering → gating → line streaming + stats.
- **Why:** detection quality is irrelevant if traversal misses `.env` or chokes on binaries.
- **Tasks:** `discovery.py` (iterative scandir, symlink no-follow default, inode loop set), `filters.py` (defaults + globs), `gating.py` (NUL sniff, size caps, BOM), `reader.py` (truncation flags), `orchestrator.py` (budgets, error accounting), `models/stats.py`, `utils/paths.py`.
- **Impact:** creates the I/O half of the pipeline; detectors plug into `reader` output in Phase 3–6.
- **Dependencies:** Phase 1 config (excludes/limits).
- **Testing:** `test_scan_tree` + `test_fs_edges` (minus findings assertions - stats/skip reasons only) + symlink-loop termination test.
- **Done:** synthetic tree yields exact `files_scanned/skipped_binary/excluded/oversize/errored` counts; 5 MB one-liner completes bounded; broken symlink doesn't abort.
- **Risks:** Windows path/symlink semantics - test on Windows + POSIX from day one.

### Phase 3 - Detection rule engine

- **Goal:** Tier-1 signatures + validators + prefilter + `Rule`/`Finding` models + `rules --list/--show`, `explain`.
- **Why:** first end-to-end findings (even before entropy/context tuning).
- **Tasks:** `models/rule.py + finding.py` (fingerprint, sort), `rules/*.py` Tier-1 set, `detectors/signatures.py`, `detectors/heuristics.py` (JWT/DB/PEM validators, pair booster), `cli` rules/explain commands.
- **Impact:** detector contract frozen (line-tuple in, provisional findings out).
- **Dependencies:** Phase 2 reader.
- **Testing:** per-rule positive/negative fixtures (placeholders must fail), validator tests, prefilter-recall test, ReDoS budget test.
- **Done:** every Tier-1 rule has ≥5 pos / ≥10 neg passing; `explain SS-GITHUB-001` renders rule card.
- **Risks:** Discord/generic regex FP blowout - ship with context-required gates from day one, not as a fix later.

### Phase 4 - Entropy and heuristic intelligence

- **Goal:** Shannon analyzer + encoding guess + thresholds + margin scoring + data-URI/hash/UUID pre-gates.
- **Why:** catches unknown secrets; must be gated so it doesn't drown signatures in noise.
- **Tasks:** `detectors/entropy.py`, `[entropy]` config wiring, tuning pass over corpus (record chosen values + precision/recall table in code comments for v1.0 docs).
- **Dependencies:** Phase 3 candidates.
- **Testing:** hand-computed H vectors, boundary tests, minified/lockfile gating tests, rule-cost timing probe.
- **Done:** generic-path true positives (synthetic high-entropy assignments) fire; UUID/hash fixtures stay silent; entropy share of runtime measured.
- **Risks:** over-detection - hard rule: entropy-alone never fires (enforced by test).

### Phase 5 - Context analysis

- **Goal:** whole-token key/file/dir/comment signals + strong/weak/benign tiers + provider keyword boosts.
- **Why:** the precision lever for generic rules and the confidence lever for signatures.
- **Tasks:** `detectors/context.py` (tokenizer, hint sets, filename signals), wire ctx into scoring (Phase 6 stub values first).
- **Dependencies:** Phases 3–4.
- **Testing:** `monkey`/`keyboard` negatives, `.env.example` cap, test/fixture demotion, provider-boost cases.
- **Done:** §12.3 decision table fully asserted; context-off ablation shows FP increase (recorded, proves the module earns its keep).
- **Risks:** substring-matching regression - tokenizer test suite is the guardrail.

### Phase 6 - Confidence and severity system

- **Goal:** deterministic formula (§14) + severity map + bands + demotion caps + reason codes on every finding.
- **Why:** turns signals into trustworthy, sortable, CI-gatable output.
- **Tasks:** `detectors/scoring.py`, `detectors/fp_filters.py` (ordered gates + suppress stats), fingerprint/dedup, sort-key.
- **Dependencies:** Phases 3–5.
- **Testing:** locked worked examples (§14.4), severity-orthogonality property test, allowlist/ignore tests, dedup tests.
- **Done:** golden findings (redacted) match hand-computed confidence ±0; INFO never fails CI (test).
- **Risks:** magic-number drift - all weights live in ONE module with comment rationale + tests lock them.

### Phase 7 - CLI experience

- **Goal:** polished human renderer, `--quiet/--verbose/--no-color`, progress/stats, `--version` branding, error UX.
- **Why:** first impression = CLI; must feel like a product, not a script.
- **Tasks:** `reporting/human.py`, `cli/app.py` controller, `utils/sanitize.py`, `utils/redact.py`, TTY/`NO_COLOR` logic, stderr warning taxonomy.
- **Dependencies:** Phases 1–6.
- **Testing:** golden human snapshots (redacted), color on/off matrix, escape-injection render tests, error-message tests (bad path/config).
- **Done:** sample run matches §25.1 layout; no raw values under any flag (property test incl. `--verbose`).
- **Risks:** gold-plating (spinners, banners) - forbidden by §25 spec; review enforces restraint.

### Phase 8 - Reporting and JSON output

- **Goal:** stable JSON-v1 (§26.2) + `--output` + `config_snapshot` + exit-code controller (§27).
- **Why:** CI and researcher workflows depend on machine output + codes.
- **Tasks:** `reporting/json_report.py`, exit-code logic in `app.py`, field-name freeze test, `--fail-on` vs `--severity` independence test.
- **Dependencies:** Phase 7.
- **Testing:** schema field lock, sort determinism (double-scan + shuffled-walk), exit-code 0/1/2 matrix, `--output` file write.
- **Done:** JSON validates against documented shape; same tree → byte-identical `findings` across runs.
- **Risks:** leaking raw values via new fields - schema test asserts allowlisted keys only.

### Phase 9 - False-positive controls

- **Goal:** harden §16 gates to release quality: placeholder/allowlist UX, per-rule FP notes, FP-corpus zero-above-LOW gate.
- **Why:** precision is the release blocker.
- **Tasks:** curate placeholder/safe sets, `[[allow.fingerprint]]` + `[[allow.path_rule]]` support, ignore-security docs text (for future docs), FP corpus expansion from Phases 3–6 misses.
- **Dependencies:** Phases 3–6, 8.
- **Testing:** `test_fp_corpus` gate (zero findings ≥ MEDIUM on FP corpus), allowlist round-trip tests, `--strict` reserved-name rejection (flag absent → clean error naming the future).
- **Done:** FP corpus gate green; every Tier-1 rule has `fp_notes` + remediation text reviewed.
- **Risks:** allowlist-as-footgun - fingerprints (not paths) are the documented primary mechanism; path rules require exact rule+glob.

### Phase 10 - Git integration (stub + L0 hardening)

- **Goal:** MVP ships L0 only; stub future flags with clean errors; architecture proves Git isolation.
- **Why:** satisfy "future-ready without overcomplicated MVP."
- **Tasks:** `git/__init__.py` stub (`--staged/--unstaged/--max-commits` rejected with "planned post-v1.0" + exit 2), `.git/` exclusion tests, `git`-absent environments verified (tarballs).
- **Dependencies:** Phase 2.
- **Testing:** scan inside a real `git init` tree (with staged secrets) still finds working-tree hits without invoking `git`; stub flags error cleanly.
- **Done:** no `git` subprocess in MVP (static test); `.git/` never descended.
- **Risks:** scope bleed into L1 - forbidden; L1 is v1.0 work with its own branch.

### Phase 11 - Testing and security hardening

- **Goal:** close coverage, perf smoke, redaction/ReDoS/escape/config-abuse gates green; self-scan clean.
- **Why:** a security tool's release criterion is its test suite.
- **Tasks:** fill coverage to MVP bar (≥80% scan/detect), add §34 security tests, run §35 S/M smoke + adversarial, fix all high-severity self-findings, privacy/offline test.
- **Dependencies:** all prior.
- **Testing:** meta - the suite itself (mutation spot-check on scoring weights: flip a weight → tests must fail).
- **Done:** `pytest` green on Windows+Linux, Python floor + latest; self-scan `--fail-on medium` clean (with documented fixture exclusion, not code suppression).
- **Risks:** flaky timing tests - budgets tested as "completes + bounded", never exact milliseconds.

### Phase 12 - Documentation (content spec; files created here, not now)

- **Goal:** write the docs defined in the documentation strategy (below): README, install, quickstart, CLI ref, coverage, config, custom-rules-note (future), FP/ignore guide, security + privacy models, architecture, contributing, release process, license note.
- **Why:** publishable quality requires docs that answer "is it safe? is it private? how do I suppress X?" in one sitting.
- **Tasks:** author docs from this plan's normative sections; generate CLI ref from `--help` (no drift); rules-coverage table generated from registry (script, not hand list).
- **Dependencies:** frozen CLI + rules + JSON shape.
- **Testing:** docs-code consistency test (rules table row count == registry size; `--help` snapshot in docs matches parser).
- **Done:** a new user can install → scan → interpret → suppress → gate CI from docs alone.
- **Risks:** docs drift - generation scripts + tests, not manual tables.

**Documentation strategy (what Phase 12 produces):** README (badgeless, icon header, 60-second quickstart, privacy box, exit-code table), INSTALL (pip/pipx, Python floor, offline wheel), QUICKSTART (5 commands), CLI-REFERENCE (every flag + examples), DETECTION-COVERAGE (per-rule card: ID, pattern essence, severity, confidence base, FP notes), CONFIGURATION (annotated `secretsieve.toml`), FALSE-POSITIVES (decision tree: placeholder → allowlist-fingerprint → path-rule → inline-ignore with security warning), IGNORE-MECHANISMS (same, with auditability notes), SECURITY-MODEL (§32 summary), PRIVACY-MODEL (§6 guarantees), ARCHITECTURE (pipeline diagram + module contracts), CONTRIBUTING (rule-addition checklist, fixture requirements, ReDoS review), RELEASE-PROCESS (versioning, changelog, license gate), LICENSE (file, not doc).

### Phase 13 - Packaging and release preparation

- **Goal:** `pip install secretsieve` + `pipx` verified, version stamping, changelog started, license gate closed, release checklist green.
- **Why:** Definition of Done (§47) is release-shaped, not code-shaped.
- **Tasks:** entry-point + `python -m` parity, sdist/wheel build, offline install test, version/attribution strings, license file (blocking), final acceptance run (§46).
- **Dependencies:** Phase 12 + license decision (§40).
- **Testing:** clean-venv install + scan smoke on both OSes; wheel contents audit (no tests/fixtures/secrets in wheel).
- **Done:** §47 all boxes checked; tag `v0.1.0`; no public upload until license present.
- **Risks:** last-minute dep addition - freeze; any new dep restarts Phase 11 security review.

---

## 45. Risks and Mitigations

| # | Risk | Impact | Mitigation (concrete) |
|---|------|--------|-----------------------|
| R1 | Too many false positives → tool ignored | Fatal adoption risk | Context-required gates for generic rules; entropy-never-alone invariant (tested); FP corpus gate (zero ≥ MEDIUM); per-rule precision measured before v1.0 Tier-2 |
| R2 | Too many false negatives → false confidence | Security risk | Tier-1 covers highest-prevalence formats; validators (not looser regex) raise recall safely; prefilter-recall test; docs honestly state "best-effort, not proof of absence" |
| R3 | Regex performance / ReDoS | Hang on adversarial input | Bounded repetitions, no nested quantifiers, prefilter, per-pattern 100 ms adversarial budget test, caps on lines/candidates |
| R4 | Entropy over-detection (hashes, bundles, UUIDs) | Noise flood | Pre-entropy hash/UUID/data-URI gates; generated-file threshold shift; lockfile entropy-off; tuning pass with recorded numbers |
| R5 | Huge repos (100k files, GBs) | OOM/slow CI | Stat-first gating, streaming, 5 MB cap, per-file budgets, deterministic early-skip stats; perf harness + documented bounds; `--jobs` only if proven |
| R6 | Terminal/output secret leaks | Severe (tool becomes exfil vector) | `redact()` at Finding construction; fixed-length masks; no raw field in schema; `--verbose` audited; escape sanitization; property tests over all renderers |
| R7 | Configuration complexity → mis-scans | Silent gaps | Tiny config surface (§28), unknown-key hard error, `--validate`, explicit-path-beats-exclude rule, `--no-config` hermetic mode |
| R8 | Rule maintenance burden | Rot as providers change formats | One-file-per-family, stable IDs, per-rule fixtures (change breaks tests loudly), coverage table generated from registry, Tier-2 precision bar |
| R9 | Dependency growth / supply chain | Bloat + CVEs in a security tool | Zero runtime deps MVP; any addition needs ADR + activity + license + offline-install checks |
| R10 | Poor CLI UX (clutter, colors in CI, unstable order) | CI breakage, distrust | Spec'd layout (§25), TTY-gated color, deterministic sort, golden snapshots, `--quiet`/`--json` contracts |
| R11 | Overengineering (frameworks, concurrency, Git history in MVP) | Missed release | Phase gates forbid L1+/concurrency/custom-rules in MVP; ~3–4k line budget; review checklist asks "what did you NOT build?" |
| R12 | Inline-ignore abuse hides real secrets | Audit risk | Line-only scope, exact-token match, `--verbose` accounting, documented `--strict` future; fingerprints as preferred mechanism |
| R13 | No license at release | Legal block | §40 blocking gate in Phase 13; no public upload without `LICENSE`; default all-rights-reserved stated here |

---

## 46. Acceptance Criteria

MVP (`v0.1.0`) ships iff ALL hold (verified by the suite + manual checklist):

1. `pip install -e .` then `secretsieve .`, `secretsieve scan .`, `python -m secretsieve .` all work on Windows + Linux, Python floor + latest.
2. Tier-1 rules detect every `tests/fixtures/positive/` case with correct rule ID + severity, and fire zero findings ≥ MEDIUM on `tests/regression/fp-corpus/`.
3. Confidence worked examples (§14.4) match exactly; severity never changes with confidence (property test).
4. No raw secret bytes appear in human, `--verbose`, `--quiet`, JSON, stderr, or exception output for the full fixture set (property test).
5. Exit codes: clean tree → 0; secret tree → 1; bad config/path → 2; `--fail-on` matrix tested; INFO never causes 1.
6. JSON field names match §26.2 exactly; double-scan byte-identical `findings`; ordering follows §20.2.
7. Offline test passes (sockets blocked); static audit shows no network imports in scan path.
8. ReDoS budget + escape-injection + config-abuse tests green; 5 MB one-liner completes bounded.
9. `secretsieve rules --list` count == registry size; `explain` works for every Tier-1 ID; `config --init/--validate` round-trips.
10. Self-scan (`secretsieve scan . --fail-on medium` on its own repo with documented fixture exclusion) is clean.
11. License decision recorded or release explicitly held as private (no public upload without `LICENSE`).

---

## 47. Definition of Done

First serious public release (`v0.1.0` public, hardened toward v1.0) requires:

- **Detection quality:** Tier-1 precision measured on committed corpus; known-FP classes (placeholder/hash/UUID/minified/docs-example) suppressed or demoted with tests; rule cards complete with remediation.
- **False positives:** FP-corpus gate green; ignore/allowlist paths documented with security notes; inline-ignore is line-scoped + auditable.
- **CLI UX:** §25.1 layout implemented; `--quiet/--json/--verbose/--no-color` behave per spec on TTY + piped output; `--help` complete; errors actionable (no tracebacks by default).
- **Performance:** S-corpus smoke measured + recorded; adversarial bounds tested; no concurrency shipped without benchmark justification.
- **Testing:** suites from §33 green on both OSes; coverage bar met; security tests (§34) green; determinism proven.
- **Security:** §32 checklist implemented + tested; redaction audit green; config abuse handled as exit-2.
- **Packaging:** wheel/sdist build, entry-point + `python -m` parity, offline install verified, no fixtures in wheel.
- **Documentation:** Phase-12 set complete and consistency-tested (rules table == registry; help snapshot == parser).
- **Configuration:** template + loader + `--validate` shipped; unknown keys rejected; precedence CLI > file > defaults proven.
- **Error handling:** every I/O failure counted, warned once on stderr, never aborts scan; fatal errors exit 2 with one-line cause + hint.
- **Exit codes:** §27 table implemented + tested incl. display-vs-gate independence.
- **Output formats:** human + JSON-v1 frozen; `schema_version: 1`; additive-only promise documented.
- **Privacy:** §6 MUSTs implemented + offline test green; privacy guarantees printed in README + `--help` epilog.
- **Branding:** `SecretSieve` naming consistent; `© 3rabDev - https://3rabdev.online` in CLI/config/docs/package metadata; `assets/icon.webp` as README/docs/PyPI image; terminal palette monochrome + severity accents only.
- **Repository quality:** tree matches §38 intent; no `.github/`; no stray files; fixtures synthetic-only; changelog started; version single-sourced.

---

## 48. Release Strategy

- **Versioning:** Semver. `v0.1.0` MVP → `v0.2.x` detection-intelligence iterations (threshold tuning, Tier-2 batch 1) → `v0.3.x` Git-L1 + perf (`--jobs` if justified) → `v1.0.0` stable (frozen JSON-v1, tuned thresholds, full docs). Rule-loosening or threshold-lowering = minor bump + changelog; rule-tightening (fewer FPs) = patch; JSON breaking change or ID reuse = major (forbidden before v2).
- **Roadmap shape (no dates):** MVP proves usefulness (fast, precise, private, CI-gatable). v1.0 proves production-readiness (coverage, Tier-2 precision, perf numbers, docs). Future proves extensibility (custom rules, history, SARIF, baseline) without destabilizing v1.
- **Pre-release gates per version:** acceptance (§46) re-run fully; changelog entry; `explain` coverage for new rules; FP-corpus re-baselined; perf smoke compared to baseline (±20% rule); license presence re-checked (public releases only).
- **Distribution:** PyPI (`pip install secretsieve`, `pipx install secretsieve` recommended for users); sdist + wheel; `Requires-Python: >=3.10`; no Docker image in MVP/v1.0 (documented non-goal until demanded); signed-release evaluation (sigstore) listed as future.
- **No GitHub Actions:** per project constraint, releases are NOT gated on and do NOT ship Actions workflows. Generic-CI instructions (exit-code + `--json` snippets for "any CI that can run a shell command") live in docs; no `.github/` directory is created at any milestone.
- **License gate restated:** NO public upload (PyPI, GitHub public, any registry) before the §40 license decision is implemented as a `LICENSE` file. Internal/private test installs are permitted without it.

---

*End of plan. Next step (separate phase, not authorized here): execute Phase 1 per §44 using this document as the sole blueprint. This phase stops after `PLAN.md`.*
