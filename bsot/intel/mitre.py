"""
MITRE ATT&CK technique lookup.

The full enterprise STIX bundle is large, so it is fetched once, condensed to
the fields BSOT needs, and cached (30-day TTL) for offline use thereafter.
"""

from typing import Dict, List, Optional

ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

CACHE_SERVICE = "mitre"
CACHE_KEY = "enterprise-attack-condensed"


def _condense(bundle: dict) -> dict:
    """Reduce a STIX bundle to a technique lookup table."""
    techniques = {}
    groups = {}
    software = {}

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type")

        if obj_type == "attack-pattern" and not obj.get("revoked"):
            attack_id = None
            url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    url = ref.get("url", "")
                    break
            if not attack_id:
                continue

            techniques[attack_id] = {
                "id": attack_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "url": url,
                "tactics": [
                    p.get("phase_name", "")
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": obj.get("x_mitre_platforms", []),
                "detection": obj.get("x_mitre_detection", ""),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "deprecated": obj.get("x_mitre_deprecated", False),
            }

        elif obj_type == "intrusion-set" and not obj.get("revoked"):
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    groups[ref.get("external_id", "")] = {
                        "id": ref.get("external_id", ""),
                        "name": obj.get("name", ""),
                        "aliases": obj.get("aliases", []),
                    }
                    break

        elif obj_type in ("malware", "tool") and not obj.get("revoked"):
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    software[ref.get("external_id", "")] = {
                        "id": ref.get("external_id", ""),
                        "name": obj.get("name", ""),
                        "type": obj_type,
                    }
                    break

    return {
        "techniques": techniques,
        "groups": groups,
        "software": software,
        "version": bundle.get("id", ""),
    }


def load_attack_data(no_cache: bool = False, timeout: int = 120) -> dict:
    """
    Load the condensed ATT&CK dataset, fetching and caching it if needed.

    Raises RuntimeError with an actionable message on failure.
    """
    from ..cache import cache

    if not no_cache:
        cached = cache.get(CACHE_SERVICE, CACHE_KEY)
        if cached:
            return cached

    import requests

    try:
        response = requests.get(ATTACK_BUNDLE_URL, timeout=timeout)
        response.raise_for_status()
        bundle = response.json()
    except requests.exceptions.Timeout:
        raise RuntimeError(
            f"Timed out fetching the ATT&CK dataset after {timeout}s. "
            "It is a large download; retry or raise --timeout."
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Could not fetch the ATT&CK dataset: {e}")
    except ValueError:
        raise RuntimeError("The ATT&CK dataset was not valid JSON.")

    data = _condense(bundle)
    if not data["techniques"]:
        raise RuntimeError("The ATT&CK dataset contained no techniques.")

    cache.set(CACHE_SERVICE, CACHE_KEY, data)
    return data


def get_technique(data: dict, technique_id: str) -> Optional[dict]:
    """Look up one technique by ID, case-insensitively."""
    return data["techniques"].get(technique_id.upper().strip())


def search_techniques(data: dict, query: str, limit: int = 25) -> List[dict]:
    """Search techniques by name and description, best matches first."""
    query = query.lower().strip()
    scored = []

    for tech in data["techniques"].values():
        if tech.get("deprecated"):
            continue
        name = tech["name"].lower()
        if query == name:
            score = 100
        elif name.startswith(query):
            score = 75
        elif query in name:
            score = 50
        elif query in tech["description"].lower():
            score = 10
        else:
            continue
        scored.append((score, tech))

    scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
    return [tech for _, tech in scored[:limit]]


def techniques_by_tactic(data: dict, tactic: str) -> List[dict]:
    """All techniques belonging to a tactic (e.g. credential-access)."""
    tactic = tactic.lower().strip().replace(" ", "-")
    matches = [
        tech
        for tech in data["techniques"].values()
        if tactic in tech["tactics"] and not tech.get("deprecated")
    ]
    return sorted(matches, key=lambda t: t["id"])


def list_tactics(data: dict) -> Dict[str, int]:
    """Tactic names mapped to technique counts."""
    counts: Dict[str, int] = {}
    for tech in data["techniques"].values():
        if tech.get("deprecated"):
            continue
        for tactic in tech["tactics"]:
            counts[tactic] = counts.get(tactic, 0) + 1
    return dict(sorted(counts.items()))
