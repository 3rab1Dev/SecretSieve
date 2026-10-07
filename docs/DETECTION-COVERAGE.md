# Detection Coverage

Copyright (c) 3rabDev - https://3rabdev.online

24 rules. IDs are stable (`SS-<FAMILY>-<NNN>`); semantics may tighten in
patches, loosening is MINOR + changelog. `secretsieve explain <ID>` prints any card.

## Tier 1 (core)

| ID | Name | Severity | Base conf | Standalone? |
|----|------|----------|-----------|-------------|
| SS-AWS-001 | AWS Access Key ID | HIGH | 90 | yes |
| SS-AWS-002 | AWS Secret Access Key | CRITICAL | 75 | no (AWS context or paired AKIA) |
| SS-GITHUB-001 | GitHub Token | CRITICAL | 90 | yes |
| SS-JWT-001 | JSON Web Token (alias SS-GENERIC-JWT-001) | HIGH | 85 | yes (header must decode) |
| SS-PRIVATE-KEY-001 | PEM Private Key | CRITICAL | 95 | yes (one finding per block) |
| SS-GENERIC-001 | Generic API Key Assignment | MEDIUM | 30 | no (entropy required) |
| SS-GENERIC-002 | Generic Secret/Password Assignment | MEDIUM | 30 | no (short values -> LOW) |
| SS-GENERIC-003 | Bearer Token | HIGH | 80 | yes (keyword is the context) |
| SS-GENERIC-004 | Webhook/Client Secret | HIGH | 45 | no (entropy required) |
| SS-DB-001 | Database Connection String | CRITICAL | 88 | yes (localhost defaults -> LOW) |
| SS-SLACK-001 | Slack Token | HIGH | 90 | yes |
| SS-STRIPE-001 | Stripe API Key | branches | 90 | yes (sk_live CRITICAL, sk_test HIGH, pk_live MEDIUM, pk_test LOW) |
| SS-DISCORD-001 | Discord Token | HIGH | 70 | no (context + entropy) |
| SS-ENV-001 | Environment File Secret | MEDIUM | 40 | no (dotenv files only; `.env.example` -> INFO) |

## Tier 2 (extended providers)

| ID | Name | Severity | Notes |
|----|------|----------|-------|
| SS-GITLAB-001 | GitLab PAT | CRITICAL | `glpat-` prefix |
| SS-GOOGLE-001 | Google API Key | HIGH | `AIza` 39-char shape |
| SS-GCP-001 | GCP Service Account Key | CRITICAL | JSON marker; key block also fires SS-PRIVATE-KEY-001 |
| SS-AZURE-001 | Azure Connection String Key | HIGH | `AccountKey=` marker |
| SS-NPM-001 | npm Access Token | HIGH | `npm_` prefix |
| SS-PYPI-001 | PyPI API Token | HIGH | `pypi-` prefix |
| SS-OPENAI-001 | OpenAI API Key | HIGH | disambiguated from Stripe `sk_live/sk_test` |
| SS-SENDGRID-001 | SendGrid API Key | HIGH | `SG.` shape |
| SS-TWILIO-001 | Twilio API Key | HIGH | `SK` + 32 hex, Twilio context required |
| SS-SHELL-001 | Shell/Docker Secret Assignment | MEDIUM | `export`/`ENV`/`ARG` + secret-like key |

## Confidence and severity

Confidence (0-99, never 100) = base + context (+15 strong / +7 weak / -20 benign)
+ entropy bonus (+0/5/10/15 by margin) + structure (+5) + pairing (+10 AWS)
- path penalties, clamped. Severity is intrinsic to the rule + deployment
context (test/fixture/example/docs/generated demote one level; private keys in
docs stay CRITICAL). Confidence never changes severity.
