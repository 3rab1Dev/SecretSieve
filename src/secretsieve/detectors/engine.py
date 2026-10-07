"""File-level detection pipeline (PLAN Sec. 8-9).

Order per line: prefilter -> signature matches -> validators -> FP gates ->
context gate -> entropy gate -> confidence -> severity -> allowlist ->
finding creation. File-level passes add PEM block spanning, AWS AKIA/secret
pairing, and repeated-value collapsing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from secretsieve.detectors import context as context_mod
from secretsieve.detectors import fp_filters as fp
from secretsieve.detectors import heuristics as heu
from secretsieve.detectors import scoring
from secretsieve.detectors.entropy import analyze as analyze_entropy
from secretsieve.detectors.entropy import EntropyResult
from secretsieve.detectors.signatures import iter_matches, line_needs_full_scan
from secretsieve.models.config import Config
from secretsieve.models.finding import Finding, build_finding
from secretsieve.models.rule import Rule, extract_secret
from secretsieve.models.stats import ScanStats
from secretsieve.rules import RULE_REGISTRY
from secretsieve.scanner import filetypes
from secretsieve.utils import redact as redact_mod

# Rules whose generic path REQUIRES a passing entropy score (PLAN Sec. 10-11).
ENTROPY_REQUIRED = frozenset(
    {"SS-GENERIC-001", "SS-GENERIC-004", "SS-DISCORD-001", "SS-OPENAI-001", "SS-TWILIO-001"}
)

# Validators awarding a +5 structural bonus on pass.
STRUCT_BONUS_VALIDATORS = frozenset(
    {
        "jwt_structure", "pem_block", "db_url", "stripe_branch",
        "bearer_token", "gcp_service_account", "openai_key", "aws_secret",
    }
)

_AWS_BARE_40_RE = re.compile(r"""['"]([A-Za-z0-9/+=]{40})['"]""")
_AWS_AKIA_RE = re.compile(r"AKIA[0-9A-Z]{16}")

_SIG_PHRASE = {
    "SS-AWS-001": "provider signature",
    "SS-AWS-002": "provider signature",
    "SS-GITHUB-001": "prefix signature",
    "SS-GITLAB-001": "prefix signature",
    "SS-SLACK-001": "prefix signature",
    "SS-STRIPE-001": "prefix signature",
    "SS-DISCORD-001": "token shape",
    "SS-JWT-001": "JWT structure",
    "SS-PRIVATE-KEY-001": "private-key block",
    "SS-DB-001": "connection-string structure",
    "SS-GENERIC-001": "secret assignment",
    "SS-GENERIC-002": "secret assignment",
    "SS-GENERIC-003": "auth header",
    "SS-GENERIC-004": "secret assignment",
    "SS-ENV-001": "env assignment",
    "SS-GOOGLE-001": "prefix signature",
    "SS-GCP-001": "service-account marker",
    "SS-AZURE-001": "connection-string marker",
    "SS-NPM-001": "prefix signature",
    "SS-PYPI-001": "prefix signature",
    "SS-OPENAI-001": "prefix signature",
    "SS-SENDGRID-001": "key shape",
    "SS-TWILIO-001": "key shape",
    "SS-SHELL-001": "shell assignment",
}


@dataclass
class Provisional:
    rule: Rule
    secret: str
    lineno: int
    col: int
    end_col: int | None
    tier: str
    ctx_key: str | None
    reason_codes: list[str] = field(default_factory=list)
    entropy: EntropyResult | None = None
    struct_bonus: int = 0
    severity_override: str | None = None
    unsigned_jwt: bool = False
    localhost_default_db: bool = False
    short_password: bool = False


def _clean_value(raw: str) -> str:
    v = raw.strip()
    if len(v) >= 2 and v[0] in ("'", '"', "`") and v[-1] == v[0]:
        v = v[1:-1]
    v = v.strip()
    # Trailing statement terminators / JSON commas.
    v = v.rstrip(",;")
    return v.strip()


def _strip_inline_comment(value: str) -> str:
    # Only " #..." style comments (never inside the value itself).
    if " #" in value:
        head, _, _tail = value.partition(" #")
        # Keep it if the remainder looks like part of a secret (no spaces).
        if " " not in _tail and "=" not in _tail:
            return head
        return head
    return value


def _secret_key_like(key: str | None) -> bool:
    if not key:
        return False
    tokens = set(context_mod.tokenize_key(key))
    return bool(tokens & context_mod.SECRET_TOKENS)


# ---------------------------------------------------------------- validators

def _validate(rule: Rule, secret: str, line: str, rel_path: str, prov_extra: dict) -> bool:
    name = rule.validator
    if name is None:
        return True
    if name == "aws_secret":
        return True  # shape enforced by regex; context gate handles the rest
    if name == "jwt_structure":
        ok, unsigned = heu.validate_jwt(secret)
        prov_extra["unsigned_jwt"] = unsigned
        return ok
    if name == "pem_block":
        return True  # block spanning handled by the caller
    if name == "db_url":
        ok, _user, _host = heu.parse_db_url(secret)
        return ok
    if name == "stripe_branch":
        return True
    if name == "bearer_token":
        return True
    if name == "openai_key":
        # Disambiguate from Stripe sk_live_/sk_test_ shapes.
        if "sk_live_" in line or "sk_test_" in line or "pk_live_" in line or "pk_test_" in line:
            if re.search(r"(?:sk|pk)_(?:live|test)_", secret):
                return False
        return True
    if name == "env_assignment":
        return True  # key/value checks done by the caller (needs groups)
    if name == "shell_secret":
        return True
    if name == "gcp_service_account":
        return rel_path.lower().endswith(".json")
    return True


def _shellish(rel_path: str, line: str) -> bool:
    low = rel_path.replace("\\", "/").lower()
    base = low.rsplit("/", 1)[-1]
    if base.startswith("dockerfile") or base.endswith(".dockerfile") or "docker-compose" in base:
        return True
    if low.endswith((".sh", ".bash", ".zsh", ".ksh", ".mk", ".mak")) or base in ("makefile", "gnumakefile"):
        return True
    stripped = line.lstrip()
    return stripped.startswith(("export ", "ENV ", "ARG "))


# ------------------------------------------------------------------- engine

def scan_file_content(
    rel_path: str,
    lines: list[tuple[int, str, bool]],
    cfg: Config,
    stats: ScanStats,
    *,
    generated: bool = False,
    lockfile: bool = False,
) -> list[Finding]:
    active = [r for r in RULE_REGISTRY if r.id not in set(cfg.disabled_rules)]
    by_id = {r.id: r for r in active}

    low_path = rel_path.replace("\\", "/").lower()
    is_test = filetypes.is_test_path(rel_path)
    is_docs = filetypes.is_docs_path(rel_path)
    is_example = filetypes.is_env_example(rel_path) or "example" in low_path or "sample" in low_path
    is_env_example = filetypes.is_env_example(rel_path)
    is_dotenv = filetypes.is_dotenv_file(rel_path)
    is_secret_file = filetypes.is_secret_filename(rel_path)

    provisionals: list[Provisional] = []
    akia_lines: list[int] = []
    text_by_lineno: dict[int, str] = {n: t for n, t, _tr in lines}
    consumed: set[int] = set()  # PEM body lines (never double-scanned)

    for lineno, text, _trunc in lines:
        if fp.has_inline_ignore(text):
            stats.note_suppressed("ignore")
            continue
        if not line_needs_full_scan(text, rel_path, is_dotenv=is_dotenv, is_secret_file=is_secret_file):
            continue
        matches = iter_matches(text, active)
        if not matches:
            continue
        stats.candidates += len(matches)
        if _AWS_AKIA_RE.search(text):
            akia_lines.append(lineno)
        # Per-line overlap resolution: keep higher base confidence first.
        accepted_spans: list[tuple[int, int]] = []
        ordered: list[tuple[Rule, object]] = sorted(matches, key=lambda rm: (-rm[0].base_confidence, rm[0].id))
        for rule, match in ordered:
            assert not isinstance(match, str)
            # Assignment-file rules (ENV/SHELL) capture (key, value): the value
            # span is group 2, so overlap resolution compares values, not keys.
            if rule.id in ("SS-ENV-001", "SS-SHELL-001"):
                try:
                    secret_raw, start0, end0 = match.group(2), match.start(2), match.end(2)
                except Exception:
                    continue
            else:
                secret_raw, start0, end0 = extract_secret(rule, match)  # type: ignore[arg-type]
            span = (start0, end0)
            if any(s < end0 and start0 < e for s, e in accepted_spans):
                continue
            # SS-ENV-001 is file-gated to dotenv files (generic rules own .py etc.).
            if rule.id == "SS-ENV-001" and not is_dotenv:
                continue
            prov = _evaluate_match(
                rule, secret_raw, span, text, lineno, rel_path, cfg, stats,
                is_test=is_test, is_docs=is_docs, is_example=is_example,
                is_dotenv=is_dotenv, is_secret_file=is_secret_file,
                generated=generated, lockfile=lockfile,
            )
            if prov is not None:
                provisionals.append(prov)
                accepted_spans.append(span)

        # PEM block spanning: a header match consumes the following lines.
        pem_headers = [p for p in provisionals if p.rule.id == "SS-PRIVATE-KEY-001" and p.lineno == lineno]
        for ph in pem_headers:
            body_bytes, footer_lineno = _consume_pem_block(text_by_lineno, lineno, ph)
            ph.struct_bonus = 5 if footer_lineno is not None else 0
            if footer_lineno is None and "no_footer" not in ph.reason_codes:
                ph.reason_codes.append("no_footer")
            for n in range(lineno + 1, (footer_lineno or lineno) + 1):
                consumed.add(n)
            void = body_bytes
            del void

    # Drop provisionals sitting on consumed PEM body lines (except the header).
    provisionals = [p for p in provisionals if p.lineno not in consumed or p.rule.id == "SS-PRIVATE-KEY-001"]

    # AWS pairing pass: bare 40-char secrets near an AKIA line.
    if akia_lines and "SS-AWS-002" in by_id:
        _aws_pair_pass(by_id["SS-AWS-002"], text_by_lineno, akia_lines, provisionals, cfg, stats, rel_path)

    # Repeated-value collapsing: same raw value on 10+ lines -> keep first 3.
    provisionals = _collapse_repeated(provisionals, stats)

    findings: list[Finding] = []
    pair_lines = sorted(akia_lines)
    for prov in provisionals:
        finding = _finalize(
            prov, rel_path, cfg,
            is_test=is_test, is_docs=is_docs, is_example=is_example,
            is_env_example=is_env_example, generated=generated,
            pair_lines=pair_lines,
        )
        if finding is None:
            continue
        # Allowlist (fingerprint preferred, then rule+path).
        if finding.fingerprint in set(cfg.allow_fingerprints):
            stats.note_suppressed("allowlist")
            continue
        allowed = False
        for entry in cfg.allow_path_rules:
            if entry.get("rule") == finding.rule_id:
                from secretsieve.utils.paths import match_glob

                if match_glob(finding.path, str(entry.get("path", ""))):
                    allowed = True
                    break
        if allowed:
            stats.note_suppressed("allowlist")
            continue
        findings.append(finding)
    return findings


def _consume_pem_block(
    text_by_lineno: dict[int, str], header_lineno: int, prov: Provisional
) -> tuple[int, int | None]:
    """Measure PEM body bytes; return (body_bytes, footer_lineno|None). Bounded."""
    body = 0
    for n in range(header_lineno + 1, header_lineno + 101):
        line = text_by_lineno.get(n)
        if line is None:
            break
        body += min(len(line), 16 * 1024)
        if body > 16 * 1024:
            break
        if heu.PEM_FOOTER_RE.search(line):
            return body, n
    return body, None


def _evaluate_match(  # noqa: C901 - pipeline fan-out is intentional
    rule: Rule,
    secret_raw: str,
    span: tuple[int, int],
    line: str,
    lineno: int,
    rel_path: str,
    cfg: Config,
    stats: ScanStats,
    *,
    is_test: bool,
    is_docs: bool,
    is_example: bool,
    is_dotenv: bool,
    is_secret_file: bool,
    generated: bool,
    lockfile: bool,
) -> Provisional | None:
    start0, end0 = span
    col = start0 + 1  # 1-indexed start of VALUE span
    end_col = end0 + 1

    secret = _clean_value(secret_raw)

    # Rule-specific group handling for assignment-style rules.
    ctx_hint_key: str | None = None
    if rule.id == "SS-ENV-001":
        m = rule.pattern.match(line) or rule.pattern.search(line)
        if not m:
            return None
        try:
            key = m.group(1)
            secret = _clean_value(_strip_inline_comment(m.group(2)))
        except Exception:
            return None
        if not _secret_key_like(key):
            return None
        if len(secret) < 6:
            return None
        ctx_hint_key = key.casefold()
    elif rule.id == "SS-SHELL-001":
        m = rule.pattern.match(line) or rule.pattern.search(line)
        if not m:
            return None
        if not _shellish(rel_path, line):
            return None
        try:
            key = m.group(1)
            secret = _clean_value(_strip_inline_comment(m.group(2)))
        except Exception:
            return None
        if not _secret_key_like(key):
            return None
        if len(secret) < 6:
            return None
        ctx_hint_key = key.casefold()
    elif rule.id == "SS-DB-001":
        secret = secret_raw.strip()

    if not secret:
        return None

    # Line-level data-URI gate (generic/bearer/discord side only).
    if rule.id in ("SS-GENERIC-001", "SS-GENERIC-002", "SS-GENERIC-004", "SS-GENERIC-003",
                   "SS-DISCORD-001", "SS-ENV-001", "SS-SHELL-001", "SS-OPENAI-001"):
        if fp.has_data_uri(line):
            stats.note_suppressed("data_uri")
            return None

    # --- validators -----------------------------------------------------
    extra: dict = {}
    if not _validate(rule, secret, line, rel_path, extra):
        stats.note_suppressed("validator")
        return None
    reason_codes = ["prefix_match"] if rule.validator is None else ["validator_pass"]
    unsigned_jwt = bool(extra.get("unsigned_jwt"))

    # --- FP gates (ordered) ---------------------------------------------
    if fp.is_placeholder(secret, cfg.placeholder_values):
        stats.note_suppressed("placeholder")
        return None
    ctx_info = context_mod.classify(line, rel_path, lockfile=lockfile, generated=generated)
    if ctx_hint_key and ctx_info.tier in ("none", "benign_file") and _secret_key_like(ctx_hint_key):
        ctx_info = context_mod.ContextInfo("strong", ctx_hint_key, provider_hint=ctx_info.provider_hint)
    if fp.is_empty_or_default(secret, ctx_info.context_key or ctx_hint_key):
        stats.note_suppressed("empty_default")
        return None
    if fp.is_test_prefixed_value(secret):
        stats.note_suppressed("test_value")
        return None
    if rule.id in ("SS-GENERIC-002", "SS-ENV-001", "SS-SHELL-001") and fp.is_template_value(secret):
        stats.note_suppressed("template_value")
        return None

    needs_quality_gate = rule.context_required or rule.id in (
        "SS-GENERIC-003", "SS-OPENAI-001", "SS-TWILIO-001", "SS-JWT-001",
    )
    if needs_quality_gate and rule.id not in (
        "SS-AWS-001", "SS-GITHUB-001", "SS-GITLAB-001", "SS-SLACK-001",
        "SS-STRIPE-001", "SS-GOOGLE-001", "SS-NPM-001", "SS-PYPI-001",
        "SS-SENDGRID-001", "SS-AZURE-001", "SS-GCP-001",
        "SS-PRIVATE-KEY-001", "SS-DB-001",
    ):
        if fp.is_hash(secret):
            stats.note_suppressed("hash_or_uuid")
            return None
        if fp.is_uuid(secret):
            stats.note_suppressed("hash_or_uuid")
            return None
        if fp.is_css_color(secret) or fp.is_version_string(secret) or fp.is_public_identifier(secret):
            stats.note_suppressed("public_id")
            return None

    # --- context gate ----------------------------------------------------
    tier = ctx_info.tier
    if rule.context_required:
        if tier not in ("strong", "weak"):
            stats.note_suppressed("context")
            return None
        if generated and tier != "strong":
            stats.note_suppressed("generated_context")
            return None

    # --- entropy ----------------------------------------------------------
    entropy_res: EntropyResult | None = None
    entropy_bonus_pts = 0
    if rule.entropy_profile != "none":
        if lockfile and rule.id in ENTROPY_REQUIRED:
            stats.note_suppressed("lockfile_entropy_off")
            return None
        entropy_res = analyze_entropy(
            secret,
            rule.entropy_profile,
            base64_threshold=cfg.base64_threshold,
            hex_threshold=cfg.hex_threshold,
            mixed_threshold=cfg.mixed_threshold,
            min_length=cfg.entropy_min_length,
            strong_context=(tier == "strong"),
            benign_context=tier in ("benign", "benign_file"),
            generated=generated,
        )
        if rule.id in ENTROPY_REQUIRED and not entropy_res.passed:
            stats.note_suppressed("entropy")
            return None
        entropy_bonus_pts = entropy_res.bonus if entropy_res.passed else 0
        if entropy_res.passed and "high_entropy" not in reason_codes:
            reason_codes.append("high_entropy")

    # Context reason codes.
    if tier == "strong":
        reason_codes.append("strong_context")
    elif tier == "weak":
        reason_codes.append("weak_context")
    elif tier in ("benign", "benign_file"):
        reason_codes.append("benign_path")
    if unsigned_jwt:
        reason_codes.append("unsigned_jwt")

    struct_bonus = 5 if rule.validator in STRUCT_BONUS_VALIDATORS else 0
    if rule.validator is None and not rule.context_required:
        struct_bonus = 5  # full-shape prefix match

    short_password = rule.id == "SS-GENERIC-002" and len(secret) < 8
    localhost_default_db = False
    if rule.id == "SS-DB-001":
        ok, user, host = heu.parse_db_url(secret)
        void = ok
        del void
        if host in ("localhost", "127.0.0.1", "::1") and (user.casefold(), _db_pass(secret)) in {
            ("root", "root"), ("admin", "admin"), ("postgres", "postgres"),
            ("root", "password"), ("admin", "password"),
        }:
            localhost_default_db = True

    return Provisional(
        rule=rule,
        secret=secret,
        lineno=lineno,
        col=col,
        end_col=end_col,
        tier=tier,
        ctx_key=ctx_hint_key or ctx_info.context_key,
        reason_codes=reason_codes,
        entropy=entropy_res,
        struct_bonus=struct_bonus,
        unsigned_jwt=unsigned_jwt,
        localhost_default_db=localhost_default_db,
        short_password=short_password,
    )


def _db_pass(url: str) -> str:
    try:
        rest = url.split("://", 1)[1]
        userinfo = rest.split("@", 1)[0]
        return userinfo.split(":", 1)[1].casefold()
    except Exception:
        return ""


def _aws_pair_pass(
    rule: Rule,
    text_by_lineno: dict[int, str],
    akia_lines: list[int],
    provisionals: list[Provisional],
    cfg: Config,
    stats: ScanStats,
    rel_path: str,
) -> None:
    """Emit SS-AWS-002 for bare 40-char secrets near an AKIA line (paired)."""
    fired = {(p.lineno, p.col) for p in provisionals if p.rule.id == "SS-AWS-002"}
    for lineno, text in text_by_lineno.items():
        if not any(abs(lineno - a) <= 50 for a in akia_lines):
            continue
        if "SS-AWS-002" in text and "aws_secret" in text.casefold():
            continue  # already handled by the main rule
        ctx_info = context_mod.classify(text, rel_path)
        if ctx_info.tier not in ("strong", "weak"):
            continue
        for m in _AWS_BARE_40_RE.finditer(text):
            secret = m.group(1)
            if (lineno, m.start(1) + 1) in fired:
                continue
            if fp.is_placeholder(secret, cfg.placeholder_values):
                stats.note_suppressed("placeholder")
                continue
            ent = analyze_entropy(secret, "base64",
                                  base64_threshold=cfg.base64_threshold,
                                  hex_threshold=cfg.hex_threshold,
                                  mixed_threshold=cfg.mixed_threshold,
                                  strong_context=True)
            if not ent.passed:
                stats.note_suppressed("entropy")
                continue
            tier = ctx_info.tier
            provisionals.append(
                Provisional(
                    rule=rule, secret=secret, lineno=lineno,
                    col=m.start(1) + 1, end_col=m.end(1) + 1,
                    tier=tier, ctx_key=ctx_info.context_key,
                    reason_codes=["prefix_match", "paired_credential",
                                  "strong_context" if tier == "strong" else "weak_context",
                                  "high_entropy"],
                    entropy=ent, struct_bonus=5,
                )
            )
            stats.candidates += 1


def _collapse_repeated(provisionals: list[Provisional], stats: ScanStats) -> list[Provisional]:
    counts: dict[str, int] = {}
    for p in provisionals:
        counts[p.secret] = counts.get(p.secret, 0) + 1
    kept: list[Provisional] = []
    seen: dict[str, int] = {}
    for p in provisionals:
        if counts[p.secret] >= 10:
            n = seen.get(p.secret, 0)
            seen[p.secret] = n + 1
            if n >= 3:
                stats.note_suppressed("repeated_placeholder")
                continue
            if "repeated_value" not in p.reason_codes:
                p.reason_codes.append("repeated_value")
        kept.append(p)
    return kept


def _finalize(
    prov: Provisional,
    rel_path: str,
    cfg: Config,
    *,
    is_test: bool,
    is_docs: bool,
    is_example: bool,
    is_env_example: bool,
    generated: bool,
    pair_lines: list[int],
) -> Finding | None:
    rule = prov.rule
    penalties = 0
    if is_test:
        penalties += 10
    if generated:
        penalties += 10

    pair_bonus = 0
    if rule.id in ("SS-AWS-001", "SS-AWS-002") and pair_lines:
        if rule.id == "SS-AWS-002" and pair_lines:
            if any(abs(prov.lineno - a) <= 50 for a in pair_lines):
                pair_bonus = 10
                if "paired_credential" not in prov.reason_codes:
                    prov.reason_codes.append("paired_credential")
        elif rule.id == "SS-AWS-001":
            pair_bonus = 0  # AKIA stands alone; the secret gets the boost

    confidence = scoring.compute_confidence(
        base=rule.base_confidence,
        tier=prov.tier,
        entropy_bonus_pts=prov.entropy.bonus if prov.entropy and prov.entropy.passed else 0,
        struct_bonus=prov.struct_bonus,
        pair_bonus=pair_bonus,
        penalties=penalties,
    )
    if prov.tier in ("benign", "benign_file"):
        confidence = min(confidence, 60)
    if is_test or is_example:
        confidence = min(confidence, 50) if rule.context_required else confidence

    # --- severity (intrinsic; never from confidence) ----------------------
    severity = rule.severity
    if rule.id == "SS-STRIPE-001":
        variant = heu.stripe_variant(prov.secret)
        severity = {"sk_live": "CRITICAL", "sk_test": "HIGH",
                    "pk_live": "MEDIUM", "pk_test": "LOW"}.get(variant, "HIGH")
    if is_env_example:
        severity = "INFO"
    else:
        severity, _caps = scoring.adjust_severity(
            severity, is_test=is_test, is_docs=is_docs,
            is_example=is_example, generated=generated,
            is_private_key=(rule.id == "SS-PRIVATE-KEY-001"),
        )
    if prov.localhost_default_db or prov.short_password:
        severity = "LOW"

    # --- reason text -------------------------------------------------------
    sig_phrase = _SIG_PHRASE.get(rule.id, "secret pattern")
    if prov.tier == "strong":
        ctx_phrase = f"credential context ({prov.ctx_key})" if prov.ctx_key else "credential context"
    elif prov.tier == "weak":
        ctx_phrase = "weak credential context"
    elif prov.tier in ("benign", "benign_file"):
        ctx_phrase = "test/fixture context"
    else:
        ctx_phrase = "no surrounding context" if rule.context_required else "standalone match"
    reason = f"{sig_phrase} + {ctx_phrase}"

    # --- redaction ----------------------------------------------------------
    if rule.id == "SS-PRIVATE-KEY-001":
        # Header only; key body is never rendered in any form.
        redacted = f"{prov.secret.strip()} [redacted]"
        raw_for_hash = prov.secret
    elif rule.id == "SS-DB-001":
        redacted = redact_mod.redact_db_url(prov.secret)
        raw_for_hash = prov.secret
    else:
        redacted = redact_mod.redact(prov.secret)
        raw_for_hash = prov.secret

    detector = "generic" if rule.context_required else "signature"
    return build_finding(
        rule_id=rule.id, detector=detector, provider=rule.provider,
        category=rule.category, severity=severity, confidence=confidence,
        path=rel_path, line=prov.lineno, column=prov.col, end_column=prov.end_col,
        raw_value=raw_for_hash, redacted=redacted, reason=reason,
        reason_codes=list(prov.reason_codes), context_key=prov.ctx_key,
        generated=generated, truncated=False,
    )
