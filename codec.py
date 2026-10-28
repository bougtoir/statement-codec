"""Statement Codec v3 — extended core library.

Adds on top of v0.1 (base_codec):
  - bitemporal model: event_effective_at (valid time) vs event_registered_at
    (transaction time); as_of_event_time / as_known_at queries.
  - temporal statement validity: uttered_at / recorded_at / attested_at /
    valid_from / valid_until; signed validity events by authorized parties.
  - Consent manifest (multi-signature) + permission checker (suspicion of
    agreement violation vs legal determination are strictly separated).
  - Witness-cosigned checkpoints; fork/replay/deletion detection.
  - spans_cover: full-containment coverage of constraint spans in the union
    of quote spans (fixes the 1-char-overlap flaw).
  - verify_quotation returns independent fields — authenticity is never
    destroyed by expiry/withdrawal/correction/key-revocation.
"""

import copy
import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

SCHEMA_VERSION = "statement-codec-poc/0.4"

# ----------------------------------------------------------- time handling

from datetime import datetime, timezone


def parse_time(s) -> Optional[datetime]:
    """ISO-8601 → aware UTC datetime. 'Z' and offsets accepted; naive input
    is treated as UTC and flagged by callers via time_precision fields."""
    if not s:
        return None
    d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def time_le(a, b) -> bool:
    """a <= b on parsed times; None means 'unbounded' (never less)."""
    if not a or not b:
        return False
    return parse_time(a) <= parse_time(b)


STATEMENT_TYPES = (
    "speech", "campaign_promise", "policy_address", "news_comment",
    "expert_provisional", "closed_lecture", "off_record", "informal",
    "other",
)

# ---- re-export primitives (same implementation as v0.1) -------------------

def canon(obj: Any) -> bytes:
    def norm(o: Any) -> Any:
        if isinstance(o, str):
            return unicodedata.normalize("NFC", o)
        if isinstance(o, list):
            return [norm(x) for x in o]
        if isinstance(o, dict):
            return {unicodedata.normalize("NFC", str(k)): norm(v)
                    for k, v in sorted(o.items(), key=lambda kv: str(kv[0]))}
        if isinstance(o, bool) or o is None or isinstance(o, int):
            return o
        raise TypeError(f"non-canonicalizable value: {type(o)}")
    return json.dumps(norm(obj), ensure_ascii=False,
                      separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def gen_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return "ed25519:" + sha256(raw)[:16]


def pub_pem(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo
                            ).decode()


def load_pub(pem: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem.encode())


def sign_body(priv, body):
    assert "sigs" not in body and "sig" not in body
    return {"schema": SCHEMA_VERSION, "body": body,
            "sigs": [{"alg": "Ed25519",
                      "keyid": key_id(priv.public_key()),
                      "signature": priv.sign(canon(body)).hex()}]}


def add_sig(obj, priv):
    obj = copy.deepcopy(obj)
    obj["sigs"].append({"alg": "Ed25519",
                        "keyid": key_id(priv.public_key()),
                        "signature": priv.sign(canon(obj["body"])).hex()})
    return obj


def verify_sig(obj, pubs, revoked=None, signed_at=None,
               required_keyids=None):
    """Verify signature(s). required_keyids: all listed keys must have a valid
    sig (multi-sig manifests). Otherwise at least one valid sig suffices."""
    try:
        body = obj["body"]
        sigs = obj["sigs"]
    except Exception:
        return False, "malformed"
    valid = set()
    for s in sigs:
        try:
            kid = s["keyid"]
            sig = bytes.fromhex(s["signature"])
            pub = pubs[kid]
        except Exception:
            continue
        if revoked and kid in revoked and signed_at and \
                signed_at >= revoked[kid]:
            continue
        try:
            pub.verify(sig, canon(body))
            valid.add(kid)
        except Exception:
            continue
    if required_keyids is not None:
        missing = [k for k in required_keyids if k not in valid]
        if missing:
            return False, "missing-required-sigs:" + ",".join(missing)
        return True, "ok"
    if valid:
        return True, "ok"
    return False, "no-valid-signature"


# ------------------------------------------------------------------ objects

def make_consent_manifest(privs, session_id, parties, terms,
                          effective_at, version=1):
    """Multi-signed pre-interview agreement.
    parties: [{keyid, role(speaker|recorder|attendee|host), disclosure}]
    terms: machine-readable per-usage permissions, e.g.
      {recording: bool, recording_release: bool,
       direct_quote: bool, paraphrase: bool, summary: bool,
       attribution: real_name|role_only|pseudonym|anonymous,
       embargo_until: iso|null, retention_days: int|null}
    """
    body = {"type": "ConsentManifest", "manifest_id":
            "cm-" + sha256(canon([session_id, parties, terms]))[:12],
            "session_id": session_id, "parties": parties,
            "terms": terms, "effective_at": effective_at,
            "version": version}
    obj = sign_body(privs[0], body)
    for p in privs[1:]:
        obj = add_sig(obj, p)
    return obj


def make_statement(priv, session_id, text, uttered_at, recorded_at,
                   attested_at, evidence_ids, policy_id,
                   valid_from=None, valid_until=None,
                   statement_type="other",
                   commitment_start=None, commitment_end=None,
                   time_confidence="claimed", time_precision=None):
    """valid_from/until: statement_validity axis (declared period the
    content is held as the speaker's current view). UNSPECIFIED when None —
    never an infinite guarantee.
    commitment_start/end: Commitment Horizon — the period the promise/
    action/responsibility targets. Independent of validity: a campaign
    promise's validity may end at election day while its commitment window
    runs through the term; expiry does NOT erase the commitment object.
    statement_type: STATEMENT_TYPES tag used by display/verification rules;
    never forces a duration. time_precision: {field: 'second'|'minute'|...
    'unknown'} for each time field."""
    text_n = unicodedata.normalize("NFC", text)
    body = {"type": "Statement",
            "statement_id": "st-" + sha256(text_n.encode())[:12],
            "session_id": session_id, "text": text_n,
            "uttered_at": uttered_at, "recorded_at": recorded_at,
            "attested_at": attested_at,
            "valid_from": valid_from, "valid_until": valid_until,
            "statement_type": statement_type,
            "commitment_start": commitment_start,
            "commitment_end": commitment_end,
            "time_confidence": time_confidence,
            "time_precision": time_precision or {},
            "evidence_ids": evidence_ids,
            "access_policy_id": policy_id}
    return sign_body(priv, body)


def make_context_constraint(priv, statement_id, spans, kind, note,
                            author_label, created_at=""):
    body = {"type": "ContextConstraint",
            "constraint_id": "cc-" + sha256(
                canon([statement_id, spans, kind]))[:12],
            "statement_id": statement_id, "spans": spans, "kind": kind,
            "note": note, "author": author_label,
            "event_registered_at": created_at}
    return sign_body(priv, body)


def make_quotation(priv, statement, spans, quoted_text, publication,
                   transform=None, created_at="", accessed_at=""):
    body = {"type": "Quotation",
            "quote_id": "qt-" + sha256(
                canon([statement["body"]["statement_id"], spans,
                       unicodedata.normalize("NFC", quoted_text)]))[:12],
            "statement_id": statement["body"]["statement_id"],
            "statement_hash": sha256(canon(statement)),
            "spans": spans,
            "quoted_text": unicodedata.normalize("NFC", quoted_text),
            "transform": transform, "publication": publication,
            "event_registered_at": created_at, "accessed_at": accessed_at}
    return sign_body(priv, body)


def make_amendment(priv, target_id, kind, note, author_label,
                   event_effective_at="", event_registered_at=""):
    """kind: correction | retraction | dispute | validity_update |
    consent_change. Bitemporal: effective_at (valid-time) vs registered_at
    (transaction-time). Original object is never modified."""
    body = {"type": "Amendment",
            "amendment_id": "am-" + sha256(
                canon([target_id, kind, note, event_effective_at]))[:12],
            "target_id": target_id, "kind": kind, "note": note,
            "author": author_label,
            "event_effective_at": event_effective_at,
            "event_registered_at": event_registered_at}
    return sign_body(priv, body)


def make_validity_event(priv, statement_id, new_valid_from, new_valid_until,
                        note, event_effective_at, event_registered_at):
    """Signed extension/shortening of statement validity window.
    Authorization (speaker or manifest-designated authority) is checked at
    verification time against the ConsentManifest roles."""
    body = {"type": "ValidityEvent",
            "event_id": "ve-" + sha256(canon(
                [statement_id, new_valid_from, new_valid_until,
                 event_effective_at]))[:12],
            "target_id": statement_id,
            "new_valid_from": new_valid_from,
            "new_valid_until": new_valid_until,
            "note": note,
            "event_effective_at": event_effective_at,
            "event_registered_at": event_registered_at}
    return sign_body(priv, body)


# ------------------------------------------------------------------ audit log

@dataclass
class AuditLog:
    entries: List[Dict[str, Any]] = field(default_factory=list)

    def append(self, obj, registered_at=""):
        prev = self.entries[-1]["entry_hash"] if self.entries else "0" * 64
        e = {"seq": len(self.entries), "object_hash": sha256(canon(obj)),
             "object_type": obj["body"].get("type"),
             "registered_at": registered_at, "prev_entry_hash": prev}
        e["entry_hash"] = sha256(canon(e))
        self.entries.append(e)
        return e

    def checkpoint(self, operator_priv, witness_privs, at):
        """Operator + independent witnesses cosign the chain head."""
        body = {"type": "Checkpoint", "entries": len(self.entries),
                "head_hash": self.entries[-1]["entry_hash"] if self.entries
                else "0" * 64, "at": at}
        obj = sign_body(operator_priv, body)
        for w in witness_privs:
            obj = add_sig(obj, w)
        return obj

    def verify_chain(self) -> Tuple[bool, str]:
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            if e["seq"] != i or e["prev_entry_hash"] != prev:
                return False, f"chain-broken-at-{i}"
            check = {k: e[k] for k in (
                "seq", "object_hash", "object_type", "registered_at",
                "prev_entry_hash")}
            if sha256(canon(check)) != e["entry_hash"]:
                return False, f"entry-hash-mismatch-at-{i}"
            prev = e["entry_hash"]
        return True, "ok"


def detect_fork(cp_a, cp_b) -> Tuple[bool, str]:
    """Two checkpoints from (possibly divergent) mirrors."""
    if cp_a["body"]["head_hash"] == cp_b["body"]["head_hash"] and \
            cp_a["body"]["entries"] == cp_b["body"]["entries"]:
        return False, "consistent"
    return True, ("fork-or-replay: heads/lengths differ "
                  f"({cp_a['body']['entries']} vs {cp_b['body']['entries']})")


# ------------------------------------------------------------- spans (fixed)

def _covered_len(quote_spans, lo, hi) -> int:
    """Count of code points of [lo,hi) covered by union of quote_spans.

    Merges quote intervals first, then sums overlap with [lo,hi): gaps
    inside the range correctly yield partial (not zero) coverage."""
    ivs = sorted((s, e) for s, e in quote_spans if s < e and e > lo and s < hi)
    covered, cur_end = 0, None
    for s, e in ivs:
        s2, e2 = max(s, lo), min(e, hi)
        if cur_end is not None and s2 <= cur_end:
            s2 = cur_end
        if e2 > s2:
            covered += e2 - s2
            cur_end = e2
    return covered


def spans_cover(quote_spans: List[List[int]],
                constraint_spans: List[List[int]]) -> bool:
    """Every constraint span FULLY covered by union of quote spans."""
    return all(_covered_len(quote_spans, cs[0], cs[1]) == cs[1] - cs[0]
               for cs in constraint_spans)


def coverage_detail(quote_spans, constraint_spans):
    """Per-constraint coverage classification.
    Returns (status, details): status in FULL | PARTIAL | MISSING;
    details: [{span, covered_chars, total_chars, ratio}]."""
    details = []
    worst = "FULL"
    for cs in constraint_spans:
        total = cs[1] - cs[0]
        cov = _covered_len(quote_spans, cs[0], cs[1])
        ratio = (cov / total) if total else 1.0
        details.append({"span": cs, "covered_chars": cov,
                        "total_chars": total, "ratio": round(ratio, 4)})
        if cov == 0:
            worst = "MISSING"
        elif cov < total and worst == "FULL":
            worst = "PARTIAL"
    if not constraint_spans:
        worst = "FULL"
    return worst, details


# ------------------------------------------------------------- temporal axis

VALIDITY_STATES = ("EXPLICIT_ACTIVE", "EXPIRED", "FUTURE_EFFECTIVE",
                   "UNSPECIFIED", "SUPERSEDED", "WITHDRAWN", "DISPUTED",
                   "UNKNOWN")


def _roles(pkg):
    """keyid -> role, from ConsentManifest parties (registry level)."""
    r = {}
    for o in pkg["objects"]:
        if o["body"].get("type") == "ConsentManifest":
            for p in o["body"].get("parties", []):
                r[p["keyid"]] = p.get("role")
    return r


def _authorized_amendment(pkg, amend, stmt_keyid):
    """Who may amend: dispute -> anyone; correction/retraction/validity/
    consent_change -> the statement's speaker or a manifest 'host' role."""
    kind = amend["body"].get("kind") or (
        "validity_update" if amend["body"].get("type") == "ValidityEvent"
        else "")
    signer = None
    for s in amend.get("sigs", []):
        signer = s["keyid"]
        break
    if kind == "dispute":
        return True
    if kind in ("correction", "retraction", "validity_update",
                "consent_change"):
        if signer == stmt_keyid:
            return True
        return _roles(pkg).get(signer) == "host"
    return False


def statement_validity(pkg, stmt, t_event, t_known) -> Dict[str, Any]:
    """Bitemporal state of a statement.
    t_event: as_of_event_time (what was in effect then).
    t_known: as_known_at (only events registered by then count — hindsight
    is not projected into the past)."""
    b = stmt["body"]
    known = []        # authorized events with registered_at <= t_known
    for o in pkg["objects"]:
        ob = o["body"]
        if ob.get("type") not in ("Amendment", "ValidityEvent") or \
                ob.get("target_id") != b["statement_id"]:
            continue
        ra = ob.get("event_registered_at", "")
        if t_known and ra and parse_time(ra) > parse_time(t_known):
            continue  # not known yet at t_known
        if not _authorized_amendment(pkg, o,
                                     stmt["sigs"][0]["keyid"]):
            continue  # unauthorized change ignored (rejected)
        known.append(ob)

    def kind(k):
        return k.get("kind") or (
            "validity_update" if k.get("type") == "ValidityEvent" else "")
    withdrawn = any(kind(k) == "retraction" and
                    (not k.get("event_effective_at")
                     or time_le(k["event_effective_at"], t_event))
                    for k in known)
    corrected = any(kind(k) == "correction" for k in known)
    disputed = any(kind(k) == "dispute" for k in known)
    superseded = any(kind(k) == "correction" and
                     k.get("note", "").startswith("supersedes")
                     for k in known)

    vf, vu = b.get("valid_from"), b.get("valid_until")
    for k in known:
        if k.get("type") == "ValidityEvent" and \
                (not k.get("event_effective_at")
                 or time_le(k["event_effective_at"], t_event)):
            vf = k.get("new_valid_from") or vf
            vu = k.get("new_valid_until") or vu

    cs, ce = b.get("commitment_start"), b.get("commitment_end")
    if cs and parse_time(t_event) < parse_time(cs):
        commitment = "BEFORE_WINDOW"
    elif ce and parse_time(t_event) and parse_time(t_event) >= parse_time(ce):
        commitment = "PAST_DEADLINE"
    elif cs or ce:
        commitment = "IN_WINDOW"
    else:
        commitment = None  # no commitment axis declared
    # PAST_DEADLINE only reports that the window closed; fulfillment is a
    # separate fact-check and is NEVER asserted.

    if withdrawn:
        state = "WITHDRAWN"
    elif superseded:
        state = "SUPERSEDED"
    elif vf is None and vu is None:
        state = "UNSPECIFIED"
    elif vf and parse_time(t_event) and parse_time(t_event) < parse_time(vf):
        state = "FUTURE_EFFECTIVE"
    elif vu and parse_time(t_event) and parse_time(t_event) >= parse_time(vu):
        state = "EXPIRED"
    elif vf or vu:
        state = "EXPLICIT_ACTIVE"
    else:
        state = "UNKNOWN"
    flags = []
    if disputed:
        flags.append("DISPUTED")
    if corrected:
        flags.append("CORRECTED")
    return {"state": state, "flags": flags,
            "valid_from": vf, "valid_until": vu,
            "commitment_state": commitment,
            "commitment_start": cs, "commitment_end": ce,
            "statement_type": b.get("statement_type"),
            "events_applied": len(known)}


# ---------------------------------------------------------- permission check

VERDICTS = ("PERMITTED", "PROHIBITED_BY_AGREEMENT", "CONDITIONAL",
            "NO_RECORD", "SUSPECTED_VIOLATION")
# NOTE: verdicts never assert legality/illegality — agreement state only.

def check_use(pkg, stmt, usage, at, actor_role="reader") -> Dict[str, Any]:
    """Permission check against the session's ConsentManifest.
    usage: direct_quote|paraphrase|summary|recording_release|
           attribution_name|attribution_role
    Returns {verdict, reasons[]} — agreement-level only, never a legal
    determination."""
    reasons = []
    manifest = None
    for o in pkg["objects"]:
        if o["body"].get("type") == "ConsentManifest" and \
                o["body"]["session_id"] == stmt["body"]["session_id"]:
            manifest = o["body"]
    if manifest is None:
        return {"verdict": "NO_RECORD",
                "reasons": ["no consent manifest for session"]}
    t = manifest["terms"]
    pubs = pkg.get("pubs", {})
    for p in manifest["parties"]:
        pass  # parties consulted below via terms only

    # consent_change events may update terms (authorized only)
    effective = dict(t)
    for o in pkg["objects"]:
        ob = o["body"]
        if ob.get("type") == "Amendment" and \
                ob.get("kind") == "consent_change" and \
                ob.get("target_id") == manifest["manifest_id"] and \
                _authorized_amendment(pkg, o, stmt["sigs"][0]["keyid"]):
            ra = ob.get("event_registered_at", "")
            ea = ob.get("event_effective_at", "")
            if (not ea or ea <= at) and (not ra or ra <= at):
                try:
                    effective.update(json.loads(ob["note"]))
                except Exception:
                    reasons.append("consent_change unparsable (ignored)")

    if stmt["body"].get("access_policy_id") == "off-record" or \
            effective.get("off_record"):
        return {"verdict": "PROHIBITED_BY_AGREEMENT",
                "reasons": ["off-record under agreement — quotation may not "
                            "be issued under this codec (does NOT mean the "
                            "statement is false or valueless)"]}
    eu = effective.get("embargo_until")
    if eu and at < eu:
        return {"verdict": "CONDITIONAL",
                "reasons": [f"embargo until {eu}; automatic release only "
                            "if explicitly agreed"]}
    if not effective.get("recording", False) and \
            usage == "recording_release":
        return {"verdict": "PROHIBITED_BY_AGREEMENT",
                "reasons": ["recording_release not consented "
                            "(recording consent and publication consent "
                            "are separate)"]}
    if not effective.get(usage, False):
        return {"verdict": "PROHIBITED_BY_AGREEMENT",
                "reasons": [f"usage '{usage}' not granted in terms"]}
    if usage == "attribution_name" and \
            effective.get("attribution") != "real_name":
        return {"verdict": "PROHIBITED_BY_AGREEMENT",
                "reasons": [f"attribution policy is "
                            f"{effective.get('attribution')}"]}
    return {"verdict": "PERMITTED", "reasons": reasons or ["within terms"]}


# --------------------------------------------------------------- verification

def verify_quotation(pkg, quote, t_event=None, t_known=None) -> Dict[str, Any]:
    """Independent output fields; historical authenticity survives expiry,
    withdrawal, correction and (post-dated) key revocation."""
    out = {"authenticity": None, "text_match": None, "context": None,
           "dispute": False, "amendments": [], "temporal": None,
           "evidence": None, "label": None, "notes": []}
    pubs = pkg["pubs"]
    rev = pkg.get("revocations", {})
    objects = pkg["objects"]

    ok, why = verify_sig(quote, pubs, rev,
                         signed_at=quote["body"].get("event_registered_at"))
    if not ok:
        out.update(authenticity="FAIL:" + why, label="UNVERIFIABLE")
        return out

    stmts = {o["body"].get("statement_id"): o for o in objects
             if o["body"].get("type") == "Statement"}
    st = stmts.get(quote["body"]["statement_id"])
    if st is None or sha256(canon(st)) != quote["body"]["statement_hash"]:
        out.update(authenticity="FAIL:source-missing-or-changed",
                   label="UNVERIFIABLE")
        return out
    ok, why = verify_sig(st, pubs, rev,
                         signed_at=st["body"].get("attested_at"))
    out["authenticity"] = "OK" if ok else "FAIL:" + why

    # evidence quality (independent of authenticity)
    evs = st["body"].get("evidence_ids", [])
    out["evidence"] = ("present" if evs else "none-declared")

    # amendments (authorized only)
    stmt_signer = st["sigs"][0]["keyid"]
    retracted = False
    for o in objects:
        b = o["body"]
        if b.get("type") not in ("Amendment", "ValidityEvent"):
            continue
        aok, _ = verify_sig(o, pubs, rev)
        if not aok:
            out["notes"].append("amendment-signature-invalid (ignored)")
            continue
        if not _authorized_amendment(pkg, o, stmt_signer):
            if b.get("target_id") in (st["body"]["statement_id"],
                                      quote["body"]["quote_id"]):
                out["notes"].append(
                    f"unauthorized-{b.get('type')} rejected")
            continue
        tid = b.get("target_id")
        if tid in (st["body"]["statement_id"], quote["body"]["quote_id"]):
            out["amendments"].append(b.get("kind"))
            if b.get("kind") == "dispute":
                out["dispute"] = True
            if b.get("kind") == "retraction" and \
                    tid == st["body"]["statement_id"]:
                retracted = True

    # temporal axes — separate from authenticity
    out["temporal"] = statement_validity(
        pkg, st, t_event or quote["body"].get("event_registered_at", ""),
        t_known or "")

    text = st["body"]["text"]
    if any(e > len(text) or s < 0 or s > e
           for s, e in quote["body"]["spans"]):
        out["text_match"] = "MISMATCH:spans-out-of-range"
        excerpt = None
    else:
        excerpt = "".join(text[s:e] for s, e in quote["body"]["spans"])
    if excerpt is not None:
        if excerpt == quote["body"]["quoted_text"]:
            out["text_match"] = "EXACT"
        elif quote["body"].get("transform"):
            out["text_match"] = "TRANSFORMED:" + quote["body"]["transform"]
        else:
            out["text_match"] = "MISMATCH"

    # context constraints: per-constraint FULL/PARTIAL/MISSING coverage
    status_worst, all_details = "FULL", []
    for o in objects:
        b = o["body"]
        if b.get("type") == "ContextConstraint" and \
                b["statement_id"] == st["body"]["statement_id"]:
            cok, _ = verify_sig(o, pubs, rev)
            if not cok:
                out["notes"].append("constraint-signature-invalid (ignored)")
                continue
            st_status, det = coverage_detail(quote["body"]["spans"],
                                             b["spans"])
            for d in det:
                d["constraint_id"] = b["constraint_id"]
            all_details += det
            order = {"FULL": 0, "PARTIAL": 1, "MISSING": 2}
            if order[st_status] > order[status_worst]:
                status_worst = st_status
    out["context"] = {"status": status_worst, "details": all_details}

    # composite label (display only; fields above are authoritative)
    if out["authenticity"] != "OK":
        out["label"] = "UNVERIFIABLE"
    elif out["dispute"]:
        out["label"] = "DISPUTED"
    elif out["context"]["status"] != "FULL":
        out["label"] = "CONTEXT_FLAG"
    elif out["text_match"] == "EXACT":
        out["label"] = "EXACT"
    elif str(out["text_match"]).startswith("TRANSFORMED"):
        out["label"] = "TRANSFORMED"
    else:
        out["label"] = "UNVERIFIABLE"
    if retracted:
        out["notes"].append(
            "statement withdrawn — historical authenticity intact; "
            "quotation remains verifiable as past speech")
    return out
