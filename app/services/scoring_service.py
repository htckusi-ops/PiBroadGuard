import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger("pibroadguard.scoring")


@dataclass
class ScoreReason:
    type: str          # "finding_penalty", "compensation_ratio", "override"
    text: str
    impact: int        # negative = penalty, positive = bonus
    finding_id: Optional[int] = None
    rule_key: Optional[str] = None


@dataclass
class DimensionScore:
    dimension: str
    score: int
    max_score: int
    reasons: List[ScoreReason] = field(default_factory=list)
    standard_ref: str = ""


@dataclass
class ScoringResult:
    overall_rating: str
    overall_score: float
    dimensions: Dict[str, DimensionScore] = field(default_factory=dict)
    override_reasons: List[str] = field(default_factory=list)
    decision_path: str = "weighted_average"

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


# ── Broadcast-specific risk overrides ────────────────────────────────────────
# In broadcast environments certain risk factors carry higher weight than in
# classical IT.  These rule keys / question_keys trigger additional overrides.
# References: EBU R143, SMPTE ST 2059, JT-NM TR-1001-1, IEC 62443-3-2

# Rule keys that trigger a critical override when status is not compensated/accepted
BROADCAST_CRITICAL_RULE_KEYS = {
    "ptp_grandmaster_risk",       # Rogue Grandmaster – destroys whole-studio timing
}

# Combinations: if both keys are present as open findings → critical override
BROADCAST_COMBINATION_OVERRIDES = [
    (
        {"telnet_open", "mgmt_media_not_separated"},
        "Telnet + ungekoppelte Management/Media-Netze → kritisches Risiko (EBU R143)",
    ),
    (
        {"ftp_open", "mgmt_media_not_separated"},
        "FTP + ungekoppelte Management/Media-Netze → kritisches Risiko (EBU R143)",
    ),
]

# If lifecycle_score is below this and no_security_updates finding is open → extra penalty
BROADCAST_LIFECYCLE_PENALTY_THRESHOLD = 30
BROADCAST_LIFECYCLE_EXTRA_PENALTY = 10


def apply_override_rules(rating: str, findings: List[Any], scores: Dict[str, int] = None) -> str:
    critical_uncompensated = 0
    critical_total = 0
    open_rule_keys: set = set()

    for f in findings:
        sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "")) or ""
        status = (f.get("status") if isinstance(f, dict) else getattr(f, "status", "open")) or "open"
        rule_key = (f.get("rule_key") if isinstance(f, dict) else getattr(f, "rule_key", "")) or ""
        if sev == "critical":
            critical_total += 1
            if status not in ("compensated", "false_positive", "accepted"):
                critical_uncompensated += 1
        if status not in ("false_positive", "accepted", "compensated"):
            open_rule_keys.add(rule_key)

    if critical_total >= 2:
        return "red"
    if critical_uncompensated >= 1 and rating == "green":
        return "orange"

    # Lifecycle cap: lifecycle score < 20 → maximum yellow (cannot be green)
    if scores and scores.get("lifecycle", 100) < 20 and rating == "green":
        return "yellow"

    # Broadcast override: PTP grandmaster risk as open finding → cap at orange
    if open_rule_keys & BROADCAST_CRITICAL_RULE_KEYS and rating == "green":
        return "orange"

    # Broadcast combination overrides → force orange minimum
    for combo_keys, _reason in BROADCAST_COMBINATION_OVERRIDES:
        if combo_keys.issubset(open_rule_keys) and rating in ("green",):
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
    final_rating = apply_override_rules(base_rating, use, scores)
    return {**scores, "overall_rating": final_rating}


def recalculate_detailed(findings: List[Any], findings_dicts: List[Dict] = None) -> ScoringResult:
    """
    Returns a ScoringResult with per-dimension reasons for the UI score explanation panel.
    """
    use = findings_dicts if findings_dicts is not None else findings

    # Build dimension scores with reasons
    dim_scores: Dict[str, DimensionScore] = {}
    raw_scores = {dim: 100 for dim in SCORE_DIMENSIONS}

    for dim, meta in SCORE_DIMENSIONS.items():
        dim_scores[dim] = DimensionScore(
            dimension=dim,
            score=100,
            max_score=100,
            reasons=[],
            standard_ref=meta["standard_ref"],
        )

    for f in use:
        if isinstance(f, dict):
            severity = f.get("severity", "info")
            status = f.get("status", "open")
            affects = f.get("affects_score", "technical")
            title = f.get("title", f.get("rule_key", "Unknown"))
            finding_id = f.get("id")
            rule_key = f.get("rule_key")
        else:
            severity = getattr(f, "severity", "info") or "info"
            status = getattr(f, "status", "open") or "open"
            affects = getattr(f, "affects_score", "technical") or "technical"
            title = getattr(f, "title", "") or ""
            finding_id = getattr(f, "id", None)
            rule_key = getattr(f, "rule_key", None)

        if affects not in dim_scores:
            affects = "technical"

        if status in ("false_positive", "accepted"):
            continue

        penalty = SEVERITY_PENALTY.get(severity, 0)
        if status == "compensated":
            original = penalty
            penalty = penalty // 2
            reason_text = f"{title} [{severity.upper()}] – {original} Pkt. Strafe, halbiert durch Kompensation auf {penalty} Pkt."
        else:
            reason_text = f"{title} [{severity.upper()}] – {penalty} Pkt. Strafe"

        if penalty > 0:
            dim_scores[affects].reasons.append(ScoreReason(
                type="finding_penalty",
                text=reason_text,
                impact=-penalty,
                finding_id=finding_id,
                rule_key=rule_key,
            ))
            raw_scores[affects] = max(0, raw_scores[affects] - penalty)
            dim_scores[affects].score = raw_scores[affects]

    # Compensation ratio reason
    comp_required = [f for f in use if (
        (f.get("compensating_control_required") if isinstance(f, dict) else getattr(f, "compensating_control_required", False))
    )]
    comp_filled = [f for f in comp_required if (
        (f.get("compensating_control_description") if isinstance(f, dict) else getattr(f, "compensating_control_description", None))
    )]
    if comp_required:
        ratio = len(comp_filled) / len(comp_required)
        comp_score = int(ratio * 100)
        raw_scores["compensation"] = comp_score
        dim_scores["compensation"].score = comp_score
        dim_scores["compensation"].reasons.append(ScoreReason(
            type="compensation_ratio",
            text=f"{len(comp_filled)} von {len(comp_required)} Findings mit Kompensationsmassnahmen dokumentiert",
            impact=comp_score - 100,
        ))

    # Overall weighted score
    weighted = sum(
        raw_scores[dim] * meta["weight"]
        for dim, meta in SCORE_DIMENSIONS.items()
    )

    base_rating = calculate_overall_rating(raw_scores)
    override_reasons: List[str] = []
    final_rating = base_rating

    # Check overrides
    critical_uncompensated = 0
    critical_total = 0
    for f in use:
        sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "")) or ""
        status = (f.get("status") if isinstance(f, dict) else getattr(f, "status", "open")) or "open"
        if sev == "critical":
            critical_total += 1
            if status not in ("compensated", "false_positive", "accepted"):
                critical_uncompensated += 1

    open_rule_keys: set = set()
    for f in use:
        status = (f.get("status") if isinstance(f, dict) else getattr(f, "status", "open")) or "open"
        rule_key = (f.get("rule_key") if isinstance(f, dict) else getattr(f, "rule_key", "")) or ""
        if status not in ("false_positive", "accepted", "compensated"):
            open_rule_keys.add(rule_key)

    if critical_total >= 2:
        final_rating = "red"
        override_reasons.append("2 oder mehr kritische Findings → automatisch Rot")
    elif critical_uncompensated >= 1 and base_rating == "green":
        final_rating = "orange"
        override_reasons.append("1 unkompensiertes kritisches Finding → mindestens Orange")

    if raw_scores.get("lifecycle", 100) < 20 and final_rating == "green":
        final_rating = "yellow"
        override_reasons.append("Lifecycle-Score < 20 → maximal Gelb")

    # Broadcast-specific overrides
    if open_rule_keys & BROADCAST_CRITICAL_RULE_KEYS and final_rating == "green":
        final_rating = "orange"
        override_reasons.append(
            "Broadcast-Override: PTP Grandmaster-Risiko offen → mindestens Orange "
            "(SMPTE ST 2059, JT-NM TR-1001-1)"
        )
    for combo_keys, reason in BROADCAST_COMBINATION_OVERRIDES:
        if combo_keys.issubset(open_rule_keys) and final_rating == "green":
            final_rating = "orange"
            override_reasons.append(f"Broadcast-Override: {reason}")
            break

    decision_path = f"override: {override_reasons[0]}" if override_reasons else "weighted_average"

    return ScoringResult(
        overall_rating=final_rating,
        overall_score=round(weighted, 1),
        dimensions=dim_scores,
        override_reasons=override_reasons,
        decision_path=decision_path,
    )
