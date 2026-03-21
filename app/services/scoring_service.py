import logging
from typing import List, Dict, Any

logger = logging.getLogger("pibroadguard.scoring")

SEVERITY_PENALTY = {
    "critical": 30,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

SCORE_DIMENSIONS = {
    "technical": {
        "label": "Technisch",
        "standard_ref": "IEC 62443-4-2 / NIST SP 800-82",
        "weight": 0.35,
    },
    "operational": {
        "label": "Betrieb",
        "standard_ref": "IEC 62443-3-2 / NIST SP 800-82 Ch.4",
        "weight": 0.20,
    },
    "compensation": {
        "label": "Kompensation",
        "standard_ref": "IEC 62443: Compensating Countermeasures",
        "weight": 0.20,
    },
    "lifecycle": {
        "label": "Lifecycle",
        "standard_ref": "IEC 62443-4-1 / NIST SP 800-30",
        "weight": 0.15,
    },
    "vendor": {
        "label": "Hersteller",
        "standard_ref": "IEC 62443-4-1 PSIRT / SDL",
        "weight": 0.10,
    },
}


def calculate_scores(findings: List[Any]) -> Dict[str, int]:
    """
    findings: list of Finding ORM objects or dicts with .severity, .status, .affects_score (or ['affects_score'])
    """
    scores = {dim: 100 for dim in SCORE_DIMENSIONS}

    for f in findings:
        if isinstance(f, dict):
            severity = f.get("severity", "info")
            status = f.get("status", "open")
            affects = f.get("affects_score", "technical")
        else:
            severity = getattr(f, "severity", "info") or "info"
            status = getattr(f, "status", "open") or "open"
            affects = getattr(f, "affects_score", "technical") or "technical"
            # For ORM Finding objects, affects_score is stored in rule_key lookup
            # We use a workaround: store affects_score in finding's description or use rule_key

        if affects not in scores:
            affects = "technical"

        penalty = SEVERITY_PENALTY.get(severity, 0)
        if status == "compensated":
            penalty = penalty // 2

        if status not in ("false_positive", "accepted") or status == "compensated":
            scores[affects] = max(0, scores[affects] - penalty)

    # Compensation score: based on how many findings requiring compensation have it filled
    comp_required = [f for f in findings if (
        (f.get("compensating_control_required") if isinstance(f, dict) else getattr(f, "compensating_control_required", False))
    )]
    comp_filled = [f for f in comp_required if (
        (f.get("compensating_control_description") if isinstance(f, dict) else getattr(f, "compensating_control_description", None))
    )]
    if comp_required:
        ratio = len(comp_filled) / len(comp_required)
        scores["compensation"] = int(ratio * 100)

    return scores


def calculate_overall_rating(scores: Dict[str, int]) -> str:
    weighted = (
        scores["technical"] * 0.35
        + scores["operational"] * 0.20
        + scores["compensation"] * 0.20
        + scores["lifecycle"] * 0.15
        + scores["vendor"] * 0.10
    )
    if weighted >= 75:
        return "green"
    if weighted >= 55:
        return "yellow"
    if weighted >= 35:
        return "orange"
    return "red"


def apply_override_rules(rating: str, findings: List[Any]) -> str:
    critical_uncompensated = 0
    critical_total = 0

    for f in findings:
        sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "")) or ""
        status = (f.get("status") if isinstance(f, dict) else getattr(f, "status", "open")) or "open"
        if sev == "critical":
            critical_total += 1
            if status not in ("compensated", "false_positive", "accepted"):
                critical_uncompensated += 1

    if critical_total >= 2:
        return "red"
    if critical_uncompensated >= 1 and rating == "green":
        return "orange"

    return rating


def recalculate(findings: List[Any], findings_dicts: List[Dict] = None) -> Dict:
    """
    Returns dict with scores + overall_rating.
    findings: list of Finding ORM objects
    findings_dicts: optional pre-built dicts (for rule-engine output)
    """
    use = findings_dicts if findings_dicts is not None else findings
    scores = calculate_scores(use)
    base_rating = calculate_overall_rating(scores)
    final_rating = apply_override_rules(base_rating, use)
    return {**scores, "overall_rating": final_rating}
