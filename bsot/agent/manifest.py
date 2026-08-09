"""
The read-only surface offered to external consumers of the agent catalogue.

`bsot agent catalogue --json` (cli.py) already exports every command's
schema (bridge.py) and safety tier (safety.py). Before this module existed,
an external consumer of that export - the sec-team-mcp gateway, which lets
LLM specialists run a scoped subset of bsot's read-only commands -
hand-maintained its own list of which commands to expose and which of their
parameters were filesystem paths. That consumer was guessing at this repo's
internals: every parameter name in its hand-written list was wrong on the
first attempt, because parameter names are decided here, in the Click tree,
not there. This module moves the declaration to the repo that actually
knows it, so renaming or adding a command's parameters here flows straight
into the consumer with no edit on its side.

Grouped rather than a flat command list because the consumer grants groups
per discipline (detection, appsec, ...) rather than per command - see that
repo's registry for the discipline -> group mapping. Each group below is
commented with *why* it exists as a unit, not just what commands happen to
be in it, mirroring safety.py's commenting style.

Every command named anywhere in GROUPS must be tier READ_ONLY
(enforced by validate_manifest below). This manifest is a grant of
read-only access only; routing case writes or external mutations through it
is out of scope for this mechanism entirely, not a decision left to whoever
edits GROUPS next.
"""

from typing import Dict, Optional, Set, Tuple

from .bridge import build_catalogue
from .safety import Tier, tier_for

CommandPath = Tuple[str, ...]


class ManifestError(Exception):
    """Raised when GROUPS disagrees with the live Click tree or its tiers."""


# Path-parameter names, per command, per group. An empty tuple means the
# command takes no filesystem-path parameter at all - recorded deliberately
# rather than the command simply being absent from a group, and verified
# against the live catalogue by validate_manifest below rather than trusted
# from memory.
GROUPS: Dict[str, Dict[CommandPath, Tuple[str, ...]]] = {
    # Local parsing/analysis of a log file already on disk: no network, no
    # write. The LLM call that would make this genuinely risky lives in the
    # separate `logs ai-analyze` command, which is EXTERNAL_MUTATION and
    # deliberately excluded from this group.
    "log-analysis": {
        ("logs", "parse"): ("input_file",),
        ("logs", "analyze"): ("input_file",),
        ("logs", "stats"): ("input_file",),
        ("logs", "timeline"): ("input_file",),
    },
    # Pure local string/codec transforms - decode, fingerprint, or reformat
    # a blob of data, optionally read from a file instead of passed inline.
    # `timestamp` alone takes no file input (it parses a literal value and
    # format string, nothing on disk), which is why it alone declares no
    # path parameter rather than being left out of the group.
    "encoding": {
        ("data", "decode"): ("input_file",),
        ("data", "magic"): ("input_file",),
        ("data", "regex"): ("input_file",),
        ("data", "hash"): ("input_file",),
        ("data", "format"): ("input_file",),
        ("data", "timestamp"): (),
    },
    # Reference lookups against a fixed, known host (MITRE ATT&CK, NVD/
    # cve.org - see safety.py's READ_ONLY comment on that boundary). The
    # queried label is a technique or CVE ID, never a filesystem path, so
    # neither command declares one.
    "ioc-lookup": {
        ("intel", "mitre"): (),
        ("intel", "cve"): (),
    },
    # Hashing and file-type identification only - kept split from
    # file-inspect below on purpose. Merging the two would hand every
    # grantee of this narrower capability the deeper inspection commands
    # (strings/entropy/metadata) as a side effect of the merge rather than
    # as a deliberate widening someone chose.
    "file-identity": {
        ("file", "hash"): ("files",),
        ("file", "identify"): ("file_path",),
    },
    # Deeper static inspection of a single file: extracted byte strings,
    # entropy, embedded metadata. Broader than file-identity above, so it
    # stays its own group instead of being folded in - see that group's
    # comment for why the split matters.
    "file-inspect": {
        ("file", "strings"): ("file_path",),
        ("file", "entropy"): ("file_path",),
        ("file", "metadata"): ("file_path",),
    },
    # Commands whose entire job is reading something secret-shaped: scan a
    # path for embedded credentials, decode a JWT, score a password,
    # audit an SSH config for weak settings. Grouped together because
    # granting one of these means trusting a specialist with secret-
    # adjacent material generally, not with one specific file format.
    "secrets": {
        ("file", "cred-scan"): ("path",),
        ("auth", "jwt-decode"): (),
        ("auth", "password-analyze"): (),
        ("auth", "ssh-audit"): ("config_file",),
    },
    # A single command, kept as its own group rather than folded into
    # file-inspect or encoding: deobfuscating a malware payload is a
    # distinct enough capability (and a distinct enough audience) from
    # generic file inspection or codec transforms to warrant its own grant.
    "deobfuscation": {
        ("malware", "deobfuscate"): ("file_path",),
    },
}


def validate_manifest(
    groups: Optional[Dict[str, Dict[CommandPath, Tuple[str, ...]]]] = None,
) -> None:
    """
    Check `groups` against the live Click tree; fail closed at import time.

    Called with no arguments at the bottom of this module - defaulting to
    the real GROUPS - so a manifest that has drifted from the real
    commands (a renamed parameter, a retiered command, a forgotten path
    declaration) fails the moment anything imports this module, rather
    than shipping silently into a catalogue an external consumer trusts
    without re-deriving it. `groups` is only ever overridden by
    tests/agent/test_manifest.py, to exercise each failure mode against a
    deliberately broken manifest without mutating the real one.

    Four checks:

    1. Every command path named in GROUPS actually exists in
       build_catalogue() - catches a typo'd or renamed Click command path.
    2. Every declared path-parameter name actually exists in that command's
       input_schema properties - catches a typo'd or renamed parameter.
    3. Every named command is tier READ_ONLY (safety.tier_for) - this
       manifest only ever grants read-only access, so a command re-tiered
       after being added here must not keep flowing to the consumer
       silently.
    4. The symmetric check, and the one this module exists for: every
       parameter on a named command whose Click `type` is `path` or `file`
       IS declared by some group. `input_schema` alone cannot make this
       check - `_TYPE_MAP` in bridge.py collapses both `path` and `file`
       down to the JSON Schema type `"string"`, so only the `type` field in
       `_params` (added alongside this manifest) can tell a filesystem-path
       parameter apart from ordinary text. A forgotten declaration here
       isn't a missed convenience: the downstream consumer scopes
       filesystem reads to declared path parameters, so an undeclared one
       becomes an unscoped filesystem read a specialist could trigger
       through that command - exactly the class of mistake this manifest
       exists to rule out, hence checking it in both directions.
    """
    if groups is None:
        groups = GROUPS

    catalogue = {
        tuple(entry["_command_path"]): entry for entry in build_catalogue()
    }

    declared: Dict[CommandPath, Set[str]] = {}
    for group_name, commands in groups.items():
        for path, path_params in commands.items():
            entry = catalogue.get(path)
            if entry is None:
                raise ManifestError(
                    f"manifest group {group_name!r}: command "
                    f"{' '.join(path)!r} is not in build_catalogue()"
                )

            properties = entry["input_schema"]["properties"]
            for param in path_params:
                if param not in properties:
                    raise ManifestError(
                        f"manifest group {group_name!r}: "
                        f"{' '.join(path)!r} has no parameter {param!r} "
                        f"in its input_schema"
                    )

            tier = tier_for(path)
            if tier is not Tier.READ_ONLY:
                raise ManifestError(
                    f"manifest group {group_name!r}: {' '.join(path)!r} "
                    f"is tier {tier.value!r}, not read_only"
                )

            declared.setdefault(path, set()).update(path_params)

    for path, path_params in declared.items():
        entry = catalogue[path]
        for name, meta in entry["_params"].items():
            if meta.get("type") in ("path", "file") and name not in path_params:
                raise ManifestError(
                    f"{' '.join(path)!r} parameter {name!r} is Click type "
                    f"{meta['type']!r} but is not declared as a path "
                    f"parameter by any manifest group"
                )


validate_manifest()
