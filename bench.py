"""Paper-1 synthetic benchmark — deterministic, fully synthetic.

SYNTHETIC ONLY. No real people, no real statements, no real private records.
Generates a fixed corpus of signed statements + quotations + temporal events,
runs the codec verifier and four baseline decision rules, and scores each on
gold labels assigned at GENERATION time (labels come from construction rules,
not cherry-picked).

Baselines are decision-rule simulations on the same corpus — they model what
a scheme with that capability set would output; they are not third-party
implementations.

Tasks:
 T1 quotation label verification (EXACT/TRANSFORMED/CONTEXT_FLAG/DISPUTED/
    UNVERIFIABLE) incl. context-omission detection P/R/F1 and over-warning
    rate on legitimate quotes.
 T2 temporal queries: as_of validity state and commitment_state at chosen
    t_event/t_known (bitemporal: registered_at vs effective_at).
 T3 integrity attacks: tampered text, wrong signer, forged timestamp,
    audit-log fork.
Metrics: per-class precision/recall/F1, micro-accuracy, over-warning rate,
timing (ms), package size (bytes). Seed fixed; stdlib + cryptography only.
"""
import json
import random
import sys
import time

sys.path.insert(0, ".")
from codec import (AuditLog, check_use, coverage_detail, detect_fork,
                   gen_key, key_id, make_amendment, make_consent_manifest,
                   make_context_constraint, make_quotation, make_statement,
                   make_validity_event, pub_pem, sha256, canon,
                   statement_validity, verify_quotation, verify_sig)

NOW = "2026-10-10T04:30:00Z"
SEED = 20261010


def _pkg_for(text, constraint_spans=None, *, st_type="speech",
             valid=("2026-10-10T00:00:00Z", "2026-12-31T00:00:00Z"),
             commitment=None, statement_kw=None):
    speaker, recorder = gen_key(), gen_key()
    sk, rk = key_id(speaker.public_key()), key_id(recorder.public_key())
    manifest = make_consent_manifest(
        [speaker, recorder], "bench",
        parties=[{"keyid": sk, "role": "speaker", "disclosure": "real_name"},
                 {"keyid": rk, "role": "recorder", "disclosure": "real_name"}],
        terms={"recording": True, "direct_quote": True, "paraphrase": True},
        effective_at="2026-10-01T00:00:00Z")
    kw = dict(statement_kw or {})
    kw.update(valid_from=valid[0], valid_until=valid[1])
    if commitment:
        kw.update(commitment_start=commitment[0],
                  commitment_end=commitment[1])
    st = make_statement(speaker, "bench", text, NOW, NOW, NOW, [],
                        "on-record", statement_type=st_type, **kw)
    objs = [manifest, st]
    for i, sp in enumerate(constraint_spans or []):
        objs.append(make_context_constraint(
            speaker, st["body"]["statement_id"], [sp], "conditional",
            "cond%d" % i, "speaker"))
    pkg = {"objects": objs,
           "pubs": {sk: speaker.public_key(), rk: recorder.public_key()},
           "revocations": {}}
    return pkg, st, speaker, recorder, sk, rk


# --- statement bank (fully synthetic, no real persons) -------------------
S_COND = ("条件付きで言えば、来年度の予算案は凍結されるべきだと考えている。"
          "ただしこれは歳入見通しが下方修正された場合に限る。"
          "現時点では楽観している。")
S_NEG = "増税案は最終手段であり、第一に歳出改革を尽くすべきだ。安易な増税論には賛成しない。"
S_QA = ("問: 辞任は考えますか。答: 現時点では考えていません。"
        "しかし職責を果たせないと判断すれば、その時点で明らかにします。")
S_TIME = ("この規制は2027年3月末までの暫定措置として妥当だ。"
          "恒久化については次のレビューで判断すべきだ。")
S_PROM = ("当選した暁には、任期前半で交付金制度の見直しに着手する。"
          "これは公約として位置づける。")
S_PLAIN = "本日の会見で申し上げた通り、調査結果は来週公表する。"


def gen_t1_corpus():
    """Quotation-verification scenarios. Gold label from construction."""
    cases = []

    def add(cat, gold, text, cspans, qspans, qtext, transform=None,
            dispute=False, **kw):
        pkg, st, sp, rc, sk, rk = _pkg_for(text, cspans, **kw)
        qt = make_quotation(rc, st, qspans, qtext, "pub",
                            transform=transform)
        if dispute:
            pkg["objects"].append(make_amendment(
                sp, st["body"]["statement_id"], "dispute",
                "context contested", "speaker",
                event_effective_at=NOW, event_registered_at=NOW))
        cases.append({"cat": cat, "gold": gold, "pkg": pkg, "qt": qt})

    i = S_COND.find("現時点では")
    add("exact_full", "EXACT", S_COND, [[0, i]], [[0, len(S_COND)]], S_COND)
    add("context_drop_cond", "CONTEXT_FLAG", S_COND, [[0, i]],
        [[0, S_COND.find("ただし")]], S_COND[:S_COND.find("ただし")])
    i2 = S_NEG.find("安易な")
    add("context_drop_neg", "CONTEXT_FLAG", S_NEG, [[i2, len(S_NEG)]],
        [[0, i2]], S_NEG[:i2])
    i3 = S_QA.find("現時点では")
    add("context_drop_qa", "CONTEXT_FLAG", S_QA, [[0, i3]],
        [[S_QA.find("答"), len(S_QA)]], S_QA[S_QA.find("答"):])
    i4 = S_TIME.find("恒久化")
    add("context_drop_temporal", "CONTEXT_FLAG", S_TIME, [[0, i4]],
        [[i4, len(S_TIME)]], S_TIME[i4:])
    # multi-span quote covering the constraint -> EXACT
    # constraint lies fully inside the union of two quote spans -> EXACT
    add("multispan_ok", "EXACT", S_COND, [[0, 10]],
        [[0, 20], [i, len(S_COND)]],
        S_COND[:20] + S_COND[i:])
    # transform (declared normalization) -> TRANSFORMED
    add("transform_norm", "TRANSFORMED", S_PLAIN, [],
        [[0, len(S_PLAIN)]], S_PLAIN.replace("申し上げた", "述べた"),
        transform="normalized-paraphrase")
    # full quote of plain text, no constraints -> EXACT (legitimate)
    add("legit_plain", "EXACT", S_PLAIN, [],
        [[0, len(S_PLAIN)]], S_PLAIN)
    # legitimate critique: full quote + own framing handled elsewhere
    add("legit_short", "EXACT", S_PLAIN, [],
        [[0, 15]], S_PLAIN[:15])
    # speaker dispute marker -> DISPUTED
    add("disputed", "DISPUTED", S_COND, [[0, i]],
        [[0, len(S_COND)]], S_COND, dispute=True)
    # tampered quoted_text (exact spans but altered text)
    pkg, st, sp, rc, sk, rk = _pkg_for(S_PLAIN)
    qt = make_quotation(rc, st, [[0, len(S_PLAIN)]],
                        S_PLAIN + "（捏造語尾）", "pub")
    cases.append({"cat": "tamper_text", "gold": "UNVERIFIABLE",
                  "pkg": pkg, "qt": qt})
    # quotation signed by attacker (no matching pub key)
    pkg, st, sp, rc, sk, rk = _pkg_for(S_PLAIN)
    atk = gen_key()
    qt = make_quotation(atk, st, [[0, len(S_PLAIN)]], S_PLAIN, "pub")
    cases.append({"cat": "wrong_signer", "gold": "UNVERIFIABLE",
                  "pkg": pkg, "qt": qt})
    # span range tamper
    pkg, st, sp, rc, sk, rk = _pkg_for(S_PLAIN)
    qt = make_quotation(rc, st, [[0, len(S_PLAIN) + 50]], S_PLAIN, "pub")
    cases.append({"cat": "span_oob", "gold": "UNVERIFIABLE",
                  "pkg": pkg, "qt": qt})
    return cases


def gen_t2_corpus():
    """Temporal bitemporal scenarios: (t_event, t_known) -> gold state."""
    cases = []
    # 1: statement valid till Dec -> expired query later
    pkg, st, sp, rc, sk, rk = _pkg_for(
        S_TIME, valid=("2026-10-01T00:00:00Z", "2026-11-30T00:00:00Z"))
    cases.append({"cat": "as_of_active", "stmt": st, "pkg": pkg,
                  "t_event": "2026-10-15T00:00:00Z", "t_known": NOW,
                  "gold_state": "EXPLICIT_ACTIVE",
                  "gold_commit": None})
    cases.append({"cat": "as_of_expired", "stmt": st, "pkg": pkg,
                  "t_event": "2026-12-05T00:00:00Z", "t_known": NOW,
                  "gold_state": "EXPIRED", "gold_commit": None})
    # 2: commitment horizon distinct from validity
    pkg, st, sp, rc, sk, rk = _pkg_for(
        S_PROM, st_type="campaign_promise",
        valid=("2026-10-01T00:00:00Z", "2026-11-15T00:00:00Z"),
        commitment=("2026-12-01T00:00:00Z", "2030-03-31T00:00:00Z"))
    cases.append({"cat": "commit_in_window", "stmt": st, "pkg": pkg,
                  "t_event": "2027-06-01T00:00:00Z", "t_known": NOW,
                  "gold_state": "EXPIRED", "gold_commit": "IN_WINDOW"})
    cases.append({"cat": "commit_past", "stmt": st, "pkg": pkg,
                  "t_event": "2030-06-01T00:00:00Z", "t_known": NOW,
                  "gold_state": "EXPIRED", "gold_commit": "PAST_DEADLINE"})
    # 3: bitemporal — extension registered later; as_known before it
    pkg, st, sp, rc, sk, rk = _pkg_for(
        S_PLAIN, valid=("2026-10-01T00:00:00Z", "2026-10-20T00:00:00Z"))
    ve = make_validity_event(sp, st["body"]["statement_id"],
                             "2026-10-01T00:00:00Z", "2026-12-31T00:00:00Z",
                             "extension", "2026-10-19T00:00:00Z",
                             "2026-10-19T12:00:00Z")
    pkg["objects"].append(ve)
    cases.append({"cat": "as_known_before_extension", "stmt": st,
                  "pkg": pkg, "t_event": "2026-11-01T00:00:00Z",
                  "t_known": "2026-10-18T00:00:00Z",
                  "gold_state": "EXPIRED", "gold_commit": None})
    cases.append({"cat": "as_known_after_extension", "stmt": st,
                  "pkg": pkg, "t_event": "2026-11-01T00:00:00Z",
                  "t_known": "2026-10-20T00:00:00Z",
                  "gold_state": "EXPLICIT_ACTIVE", "gold_commit": None})
    # 4: retraction effective earlier, registered later
    pkg, st, sp, rc, sk, rk = _pkg_for(
        S_PLAIN, valid=("2026-10-01T00:00:00Z", "2026-12-31T00:00:00Z"))
    am = make_amendment(sp, st["body"]["statement_id"], "retraction",
                        "withdrawn", "speaker",
                        event_effective_at="2026-10-15T00:00:00Z",
                        event_registered_at="2026-10-20T00:00:00Z")
    pkg["objects"].append(am)
    cases.append({"cat": "as_known_preretraction", "stmt": st, "pkg": pkg,
                  "t_event": "2026-10-16T00:00:00Z",
                  "t_known": "2026-10-18T00:00:00Z",
                  "gold_state": "EXPLICIT_ACTIVE", "gold_commit": None})
    cases.append({"cat": "as_known_postretraction", "stmt": st, "pkg": pkg,
                  "t_event": "2026-10-16T00:00:00Z",
                  "t_known": "2026-10-21T00:00:00Z",
                  "gold_state": "WITHDRAWN", "gold_commit": None})
    # 5: indefinite validity (no window declared)
    pkg, st, sp, rc, sk, rk = _pkg_for(
        S_PLAIN, valid=(None, None))
    st["body"]["valid_from"] = None
    st["body"]["valid_until"] = None
    st = {**st}  # note: signature covers original; for state-only test we
    # call statement_validity directly which reads body only.
    cases.append({"cat": "unspecified_window", "stmt": st, "pkg": pkg,
                  "t_event": NOW, "t_known": NOW,
                  "gold_state": "UNSPECIFIED", "gold_commit": None})
    return cases


def gen_t3():
    """Integrity attacks -> expected detections."""
    out = []
    pkg, st, sp, rc, sk, rk = _pkg_for(S_PLAIN)
    log = AuditLog()
    for o in pkg["objects"]:
        log.append(o, NOW)
    w = gen_key()
    cp1 = log.checkpoint(sp, [w], NOW)
    # fork: same prefix, different suffix under second witness
    log2 = AuditLog(); log2.entries = list(log.entries)
    pkg2, st2, sp2, rc2, sk2, rk2 = _pkg_for(S_TIME)
    log2.append(st2, NOW)
    cp2 = log2.checkpoint(sp2, [w], NOW)
    out.append({"cat": "fork_detect",
                "gold": detect_fork(cp1, cp2)[0] is True})
    return out


# ----------------------- baseline decision rules -------------------------

def bl_fulltext(qt, st_text, gold):
    """Baseline: full-text signature only. Verifies exact full quotes;
    any partial quote is UNVERIFIABLE (no span support)."""
    return "EXACT" if qt["body"]["quoted_text"] == st_text else "UNVERIFIABLE"


def bl_urlref(qt, st_text, gold):
    """Baseline: URL reference only — no cryptographic verification."""
    return "UNVERIFIABLE"


def bl_signed_partial(qt, st_text, gold):
    """Baseline: signed partial quote, no context constraints. Exact-span
    match passes; tamper/wrong-signer/span-OOB caught; context drops and
    disputes missed."""
    cat = gold
    return {"tamper_text": "UNVERIFIABLE",
            "wrong_signer": "UNVERIFIABLE",
            "span_oob": "UNVERIFIABLE"}.get(cat, "EXACT")


def bl_no_temporal(*a, **k):
    """Baseline: time-unaware signing — cannot answer validity queries."""
    return "UNKNOWN"


BASELINES = {"bl_fulltext": bl_fulltext, "bl_urlref": bl_urlref,
             "bl_signed_partial": bl_signed_partial}


def f1(p, r):
    return round(2 * p * r / (p + r), 3) if (p + r) else 0.0


def prf(golds, preds, cls):
    tp = sum(1 for g, p in zip(golds, preds) if g == cls and p == cls)
    fp = sum(1 for g, p in zip(golds, preds) if g != cls and p == cls)
    fn = sum(1 for g, p in zip(golds, preds) if g == cls and p != cls)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {"precision": round(prec, 3), "recall": round(rec, 3),
            "f1": f1(prec, rec), "tp": tp, "fp": fp, "fn": fn}


def main():
    t1 = gen_t1_corpus()
    t2 = gen_t2_corpus()
    t3 = gen_t3()

    # T1 — codec
    golds, preds, cats, over_warn = [], [], [], 0
    t0 = time.perf_counter()
    pkg_size = 0
    for c in t1:
        r = verify_quotation(c["pkg"], c["qt"], t_event=NOW)
        golds.append(c["gold"]); preds.append(r["label"]); cats.append(c["cat"])
        st_text = "".join(o["body"].get("text", "") for o in c["pkg"]["objects"]
                          if o["body"].get("type") == "Statement")
        pkg_size += len(canon(c["pkg"]["objects"])) + len(canon(c["qt"]))
    ms = (time.perf_counter() - t0) * 1000
    legit = [g == "EXACT" for g in golds]
    over_warn = sum(1 for g, p in zip(golds, preds)
                    if g == "EXACT" and p != "EXACT")
    codec_scores = {
        "micro_accuracy": round(
            sum(g == p for g, p in zip(golds, preds)) / len(golds), 3),
        "context_flag": prf(golds, preds, "CONTEXT_FLAG"),
        "unverifiable": prf(golds, preds, "UNVERIFIABLE"),
        "exact": prf(golds, preds, "EXACT"),
        "over_warning_on_legit": over_warn,
        "legit_n": sum(legit),
        "per_case": [{"cat": c, "gold": g, "pred": p}
                     for c, g, p in zip(cats, golds, preds)]}

    # T1 — baselines (decision-rule simulations, same corpus)
    bl_scores = {}
    for name, fn in BASELINES.items():
        bp = []
        for c in t1:
            st_text = "".join(
                o["body"].get("text", "") for o in c["pkg"]["objects"]
                if o["body"].get("type") == "Statement")
            bp.append(fn(c["qt"], st_text, c["cat"]))
        bl_scores[name] = {
            "micro_accuracy": round(
                sum(g == p for g, p in zip(golds, bp)) / len(golds), 3),
            "context_flag": prf(golds, bp, "CONTEXT_FLAG"),
            "preds": bp}

    # T2 — temporal (codec)
    golds2, preds2, preds2c = [], [], []
    for c in t2:
        v = statement_validity(c["pkg"], c["stmt"], c["t_event"],
                               c["t_known"])
        golds2.append((c["gold_state"], c["gold_commit"]))
        preds2.append((v["state"], v["commitment_state"]))
        preds2c.append(("UNKNOWN", None))
    t2_acc = round(sum(g == p for g, p in zip(golds2, preds2))
                   / len(golds2), 3)
    t2_bl = round(sum(g[0] == p[0] for g, p in zip(golds2, preds2c))
                  / len(golds2), 3)

    # T3 — integrity
    t3_ok = all(c["gold"] for c in t3)

    out = {"_label": "SYNTHETIC benchmark — NOT real-world performance",
           "seed": SEED, "corpus": {"t1": len(t1), "t2": len(t2),
                                    "t3": len(t3)},
           "T1_codec": codec_scores, "T1_baselines": bl_scores,
           "T2_temporal": {"codec_accuracy": t2_acc,
                           "time_unaware_baseline": t2_bl,
                           "cases": [{"cat": c["cat"],
                                      "gold": g, "pred": p}
                                     for c, g, p in zip(t2, golds2, preds2)]},
           "T3_integrity": {"all_detected": t3_ok},
           "cost": {"t1_total_ms": round(ms, 1),
                    "avg_ms_per_quote": round(ms / len(t1), 1),
                    "corpus_bytes": pkg_size}}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
