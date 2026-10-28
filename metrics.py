"""Accountability Metrics (P1) — descriptive statistics only.

NEVER computes a person-level trust score, ranking, or political judgment.
Per statement-type, reports distributions and counts; always attaches
denominator, observation window, missingness, and selection-bias caveats.
"""
from codec import parse_time


def accountability_report(pkg, as_of=None):
    """Descriptive metrics over the package's statements.
    pkg: {"objects": [...]} (pubs not needed — metrics are over content,
    authorization was already enforced at ingestion)."""
    objs = pkg["objects"]
    stmts = [o["body"] for o in objs if o["body"].get("type") == "Statement"]
    evts = [o["body"] for o in objs
            if o["body"].get("type") in ("Amendment", "ValidityEvent")]

    def days(a, b):
        if not a or not b:
            return None
        return round((parse_time(b) - parse_time(a)).total_seconds() / 86400, 2)

    by_type = {}
    for s in stmts:
        t = s.get("statement_type", "other")
        d = by_type.setdefault(t, {
            "n": 0, "validity_days": [], "commitment_days": [],
            "unspecified_validity": 0, "expired_at_asof": 0,
            "short_validity_lt_7d": 0,
            "corrections": 0, "retractions": 0, "disputes": 0,
            "validity_updates": 0, "validity_shortenings": 0})
        d["n"] += 1
        vd = days(s.get("valid_from"), s.get("valid_until"))
        if vd is None:
            d["unspecified_validity"] += 1
        else:
            d["validity_days"].append(vd)
            if vd < 7:
                d["short_validity_lt_7d"] += 1
            if as_of and parse_time(s.get("valid_until")) <= parse_time(as_of):
                d["expired_at_asof"] += 1
        cd = days(s.get("commitment_start"), s.get("commitment_end"))
        if cd is not None:
            d["commitment_days"].append(cd)
        sid = s["statement_id"]
        prev_vu = s.get("valid_until")
        for e in evts:
            if e.get("target_id") != sid:
                continue
            k = e.get("kind") or (
                "validity_update" if e.get("type") == "ValidityEvent" else "")
            if k == "correction":
                d["corrections"] += 1
            elif k == "retraction":
                d["retractions"] += 1
            elif k == "dispute":
                d["disputes"] += 1
            elif k == "validity_update":
                d["validity_updates"] += 1
                nvu = e.get("new_valid_until")
                if prev_vu and nvu and parse_time(nvu) < parse_time(prev_vu):
                    d["validity_shortenings"] += 1

    for d in by_type.values():
        d["validity_days_dist"] = sorted(d.pop("validity_days"))
        d["commitment_days_dist"] = sorted(d.pop("commitment_days"))

    return {
        "as_of": as_of,
        "denominator": {"total_statements": len(stmts),
                        "by_type_n": {t: d["n"] for t, d in by_type.items()}},
        "by_type": by_type,
        "caveats": [
            "denominator = statements present in this package only; "
            "registration coverage (登録網羅率) is unknown",
            "registration selection bias: speakers who opt in are not a "
            "representative sample",
            "metrics are descriptive distributions per type — they are not "
            "a trust score and are not comparable across types or persons",
            "short validity is legitimate for provisional/disaster-response "
            "statements; no negative judgment is implied",
            "PAST_DEADLINE commitments report a closed window only — "
            "fulfillment is a fact-check outside this codec's scope",
        ],
    }
