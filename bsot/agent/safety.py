"""
Safety layer for the agent runtime.

BSOT reads adversary-authored input: phishing bodies, file strings, log lines.
The controls here are structural rather than prompt-only, because a prompt
instruction is exactly what an attacker gets to argue with.

Tiering is per-command, not per-group. An earlier version of this module
whitelisted entire command groups (all of `file`, `logs`, etc. were
READ_ONLY), which is fail-OPEN: any command added later under a whitelisted
group became auto-runnable with no human decision, and a security review
found several already-shipped commands that should never have been in that
bucket (arbitrary write-path options, direct outbound requests/scans to an
attacker-supplied target, silent third-party LLM calls). Every command is
now classified individually below, by reading what it actually does, and
anything not classified fails closed to EXTERNAL_MUTATION.
"""

from enum import Enum
from typing import Sequence, Tuple


class Tier(Enum):
    """
    What a tool is allowed to do without a human.

    EXTERNAL_MUTATION is the "always needs a human" tier. Despite the name,
    it is not only state changes outside this host (a Cloudflare rule, a
    malware submission) - it also covers calls that let a tainted run point
    this host's own network egress or filesystem writes at a target the
    model chose (a port scan, an HTTP fetch of an attacker-supplied URL, an
    arbitrary write path, a silent call to a third-party LLM). Both shapes
    boil down to "a tainted model made this host do something to a target
    of its choosing," and both get the same gate.
    """

    READ_ONLY = "read_only"
    CASE_WRITE = "case_write"
    EXTERNAL_MUTATION = "external_mutation"


CommandPath = Tuple[str, ...]

# ---------------------------------------------------------------------------
# READ_ONLY: local reads, and per-IOC/per-hash lookups against a fixed,
# known third-party service (VirusTotal, AbuseIPDB, GreyNoise, OTX, ipinfo,
# WHOIS, NVD/cve.org/GitHub Advisories, MITRE ATT&CK, crt.sh, Have I Been
# Pwned, Cloudflare's own rule list). The indicator is a query parameter
# sent to a fixed host in these - never the connection target itself - which
# is what keeps them out of EXTERNAL_MUTATION.
# ---------------------------------------------------------------------------
_READ_ONLY: frozenset = frozenset({
    # phishing: local parsing plus fixed-host reputation lookups. (`analyze`
    # and `url` are NOT here - see EXTERNAL_MUTATION notes below.)
    ("phishing", "extract-iocs"),
    ("phishing", "headers"),
    ("phishing", "reputation"),

    # intel: all fixed-host enrichment, or pure local string ops.
    ("intel", "bulk"),
    ("intel", "cve"),
    ("intel", "defang"),
    ("intel", "enrich"),
    ("intel", "geoip"),
    ("intel", "mitre"),
    ("intel", "refang"),
    ("intel", "whois"),

    # file: local filesystem/forensics reads only. (`baseline` requires an
    # arbitrary write path and is gated - see EXTERNAL_MUTATION.)
    ("file", "cred-scan"),
    ("file", "diff"),
    ("file", "entropy"),
    ("file", "hash"),
    ("file", "identify"),
    ("file", "metadata"),
    ("file", "permissions"),
    ("file", "strings"),
    ("file", "suid-finder"),

    # network: DNS lookups go through the configured resolver (indirect,
    # like whois) rather than connecting to the target directly. `ct-
    # subdomains` queries crt.sh (a fixed host); its --resolve flag only
    # does further DNS resolution, not a connection to the target.
    # (`headers`, `ports`, `ssl-check` are NOT here - direct connections to
    # an attacker-supplied target. See EXTERNAL_MUTATION.)
    ("network", "ct-subdomains"),
    ("network", "dns"),

    # logs: local parsing/analysis only (the LLM call lives in ai-analyze).
    ("logs", "analyze"),
    ("logs", "parse"),
    ("logs", "stats"),
    ("logs", "timeline"),

    # data: pure local string/codec transforms, no I/O beyond an input file.
    ("data", "decode"),
    ("data", "encode"),
    ("data", "format"),
    ("data", "hash"),
    ("data", "magic"),
    ("data", "regex"),
    ("data", "timestamp"),

    # auth: local parsing; --check-breach hits a fixed k-anonymity API.
    ("auth", "jwt-decode"),
    ("auth", "password-analyze"),
    ("auth", "ssh-audit"),

    # system: local host state; --vt is a fixed-host hash lookup.
    ("system", "connections"),
    ("system", "persistence"),
    ("system", "processes"),

    # ir: hash-tree only reads files and hashes them - its `--output` is an
    # optional write path stripped by the bridge (bridge.py), so the write
    # target the model can influence is gone. cf list / cf test only call
    # read endpoints on the Cloudflare API. (`collect` is NOT here - see
    # EXTERNAL_MUTATION.)
    ("ir", "cf", "list"),
    ("ir", "cf", "test"),
    ("ir", "hash-tree"),

    # malware: local static analysis only. `ioc --enrich` is currently a
    # no-op stub in the code (it just prints "coming soon"), not a real
    # network lookup - reclassify if that ever gets implemented.
    # (`submit` is NOT here - uploads to third-party sandboxes.)
    ("malware", "compare"),
    ("malware", "deobfuscate"),
    ("malware", "ioc"),
    ("malware", "pe"),
    ("malware", "strings"),
    ("malware", "yara"),

    # case: read-only views of the active case.
    ("case", "list"),
    ("case", "status"),

    # report: exports of already-recorded case data (no LLM, no network).
    # (`generate` and `package` are NOT here - see the other two tiers.)
    ("report", "ioc"),
    ("report", "template"),
    ("report", "timeline"),
})

# ---------------------------------------------------------------------------
# CASE_WRITE: local writes confined to the active case's own storage. No
# network egress, no writes outside the case directory.
# ---------------------------------------------------------------------------
_CASE_WRITE: frozenset = frozenset({
    ("case", "add"),
    ("case", "close"),
    ("case", "new"),
    ("case", "note"),
    ("case", "open"),
    ("case", "timeline"),
    # Bundles the case directory into an archive file. Doesn't touch case
    # data and doesn't leave the host, but it is a new persisted artifact
    # rather than a stdout-only export like report ioc/timeline, so it's
    # treated as a write, not a read.
    ("report", "package"),
})

# ---------------------------------------------------------------------------
# EXTERNAL_MUTATION: always needs a human. Two different hazard shapes live
# here - genuine external state changes, and "a tainted run got to pick this
# host's egress or write target." See the Tier docstring.
# ---------------------------------------------------------------------------
_EXTERNAL_MUTATION: frozenset = frozenset({
    # --- Confirmed by security review ---
    # Cloudflare firewall writes: real production state change.
    ("ir", "cf", "block"),
    ("ir", "cf", "bulk-block"),
    ("ir", "cf", "unblock"),
    # Prints commands rather than executing them, but the generated
    # commands (iptables/pf/netsh rules, account-disable commands) are
    # exactly what an operator would copy-paste and run; kept gated even
    # though the process itself has no side effect.
    ("ir", "contain"),
    # Uploads a file to third-party sandboxes/scanners.
    ("malware", "submit"),
    # Fetches an arbitrary attacker-supplied URL directly.
    ("network", "headers"),
    # Port-scans an arbitrary attacker-supplied host.
    ("network", "ports"),
    # Ships log content/stats to a third-party LLM.
    ("logs", "ai-analyze"),
    # Ships the full email to a third-party LLM.
    ("phishing", "ai-analyze"),
    # Ships case contents (artifacts, IOCs, notes, timeline) to a
    # third-party LLM by default; --no-llm is something the model would
    # have to opt into, not the default path.
    ("report", "generate"),
    # Required write-target path with no safe default (bridge.py strips
    # `--output` everywhere else, but only when it's optional).
    ("file", "baseline"),

    # --- Found in this review, beyond the confirmed list above ---
    # `phishing analyze` (not just `ai-analyze`) silently ships the full
    # email to a third-party LLM whenever an OpenAI/Anthropic key is
    # available. Click's envvar= wiring on --openai-key/--anthropic-key
    # pulls from the process environment even if the model never passes a
    # key itself: see PhishingAnalyzer.analyze()'s `skip_llm=not llm_key`
    # in bsot/phishing/analyzer.py, called whenever --quick is not passed.
    # This isn't exposed as a separate command, so the whole command gates.
    ("phishing", "analyze"),
    # `phishing url --expand` makes a direct HTTP request to the
    # attacker-supplied URL to follow redirects - the same hazard shape as
    # `network headers`, just optional rather than default-on.
    ("phishing", "url"),
    # Opens a direct TCP/TLS connection to an attacker-supplied host:port
    # (bsot/network/ssl_checker.py: socket.create_connection((host, port))) -
    # the same SSRF-shaped hazard as `network ports`/`network headers`.
    ("network", "ssl-check"),
    # Composes WHOIS/DNS/SSL into one profile; the embedded SSL check opens
    # the same direct connection to the target as `network ssl-check`.
    ("osint", "domain"),
    # Writes collected forensic artifacts under `--output-dir`, a directory
    # path the model can set. Every other write-target option in this
    # codebase is named `output` and is stripped by the bridge (bridge.py);
    # this one is named `output_dir` and is not covered by that stripping,
    # so a tainted run could still steer where files land. Gated until
    # bridge.py strips this too or the option is removed.
    ("ir", "collect"),
})


def tier_for(path: Sequence[str]) -> Tier:
    """
    Classify a command path.

    `path` is read exactly once into `key` (a one-shot iterable must not be
    consumed twice), checked in order of specificity, and matched by exact
    membership only - no group fallback. A command not explicitly listed
    fails closed to EXTERNAL_MUTATION: that's what makes the exhaustiveness
    test in test_safety.py meaningful, and it means a command added later is
    gated until someone classifies it deliberately, rather than silently
    becoming auto-runnable.
    """
    key: CommandPath = tuple(path)

    if not key:
        return Tier.EXTERNAL_MUTATION

    if key in _READ_ONLY:
        return Tier.READ_ONLY
    if key in _CASE_WRITE:
        return Tier.CASE_WRITE
    if key in _EXTERNAL_MUTATION:
        return Tier.EXTERNAL_MUTATION

    return Tier.EXTERNAL_MUTATION


def requires_approval(path: Sequence[str], tainted: bool) -> bool:
    """
    Whether a human must approve this call.

    External mutations always require approval. A tainted run - one that has
    ingested attacker-controlled content - may not mutate anything at all
    without a human, regardless of what the model concluded from that content.
    """
    tier = tier_for(path)
    if tier is Tier.EXTERNAL_MUTATION:
        return True
    return tainted and tier is not Tier.READ_ONLY
