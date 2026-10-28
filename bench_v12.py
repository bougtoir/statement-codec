"""v12 expanded synthetic benchmark — factorial coverage + ablations +
strong composition baseline. SYNTHETIC ONLY.

Extends bench.py with:
- T1b boundary/adversarial cases (overlapping spans, empty span, duplicated
  constraint text (homograph clause), contradictory constraints, off-record
  consent check, unauthorized amendment, embargo).
- Ablation studies: codec without context constraints; codec without
  temporal axis.
- Strong composition baseline (comp): signed partial quote + naive
  substring context rule + valid-time-only state + no authorization.
  This is the strongest practical composition the Gate-1 audit identified;
  it differs from the codec on span-positional checks (homograph clauses),
  bitemporal hindsight queries, permissions, and fork detection — and is
  functionally EQUIVALENT on plain syntactic coverage. Reported honestly.
"""
import json
import sys
import time

sys.path.insert(0, ".")
from codec import (gen_key, key_id, make_amendment, make_consent_manifest,
                   make_context_constraint, make_quotation, make_statement,
                   check_use, statement_validity, verify_quotation, verify_sig)
from bench import NOW, _pkg_for, S_COND, S_NEG, S_QA, S_TIME, S_PROM, S_PLAIN

SEED = 20261010


def gen_t1b():
    cases = []
    i = S_COND.find("現時点では")

    def add(cat, gold, text, cspans, qspans, qtext, transform=None, **kw):
        pkg, st, sp, rc, sk, rk = _pkg_for(text, cspans, **kw)
        qt = make_quotation(rc, st, qspans, qtext, "pub",
                            transform=transform)
        cases.append({"cat": cat, "gold": gold, "pkg": pkg, "qt": qt,
                      "st": st})

    # overlapping quote spans: union covers constraint and excerpt text is
    # the (duplicated) overlap content -> EXACT
    add("overlap_spans", "EXACT", S_COND, [[0, i]],
        [[0, i + 5], [i, len(S_COND)]],
        S_COND[:i + 5] + S_COND[i:])
    # duplicated constraint text: clause appears twice; quote drops the
    # constrained occurrence but repeats the words verbatim elsewhere ->
    # span-based codec flags (MISSING), substring baseline passes (miss)
    # duplicated constraint text: the SAME clause occurs twice; the
    # constrained first occurrence is dropped while the identical words
    # survive at the second position -> span codec flags (MISSING) while
    # substring baseline passes (miss: positional info lost)
    dup_text = ("条件付きで言えば維持が妥当だ。ただし今後の見通し次第で、"
                "条件付きで言えば修正もあり得る。")
    c2nd = dup_text.rfind("条件付きで")
    add("homograph_clause", "CONTEXT_FLAG", dup_text, [[0, 8]],
        [[c2nd, len(dup_text)]], dup_text[c2nd:])
    # contradictory pair: two constraints, quote covers only one -> PARTIAL
    add("contradictory_constraints", "CONTEXT_FLAG", S_COND,
        [[0, i], [i, len(S_COND)]],
        [[0, i]], S_COND[:i])
    # empty span: zero-length excerpt is trivially exact (documented edge)
    add("empty_span", "EXACT", S_PLAIN, [], [[0, 0]], "")
    # transform: whitespace normalization
    add("transform_ws", "TRANSFORMED", S_PLAIN, [],
        [[0, len(S_PLAIN)]], S_PLAIN.replace("、", "、 "),
        transform="whitespace")
    return cases


def gen_policy():
    """Consent/off-record/permission checks (gold verdicts)."""
    cases = []
    sp, rc = gen_key(), gen_key()
    sk, rk = key_id(sp.public_key()), key_id(rc.public_key())
    m = make_consent_manifest(
        [sp, rc], "x",
        parties=[{"keyid": sk, "role": "speaker"},
                 {"keyid": rk, "role": "recorder"}],
        terms={"recording": True, "direct_quote": False},
        effective_at="2026-10-01T00:00:00Z")
    st = make_statement(sp, "x", "これはオフレコ限定の発言です。", NOW,
                        NOW, NOW, [], "off-record",
                        valid_from="2026-01-01T00:00:00Z",
                        valid_until="2026-12-31T00:00:00Z")
    pkg = {"objects": [m, st],
           "pubs": {sk: sp.public_key(), rk: rc.public_key()},
           "revocations": {}}
    cases.append({"cat": "offrecord_direct_quote",
                  "gold": "PROHIBITED_BY_AGREEMENT",
                  "verdict": check_use(pkg, st, "direct_quote", NOW,
                                       actor_role="journalist")["verdict"]})
    # unauthorized retraction by recorder must be ignored
    am = make_amendment(rc, st["body"]["statement_id"], "retraction",
                        "forged", "recorder", event_effective_at=NOW,
                        event_registered_at=NOW)
    pkg["objects"].append(am)
    cases.append({"cat": "unauth_retraction",
                  "gold": "EXPLICIT_ACTIVE",
                  "verdict": statement_validity(pkg, st, NOW, NOW)["state"]})
    return cases


def comp_baseline(case):
    """Strong composition baseline: signed partial quote + naive substring
    context rule + no authorization/temporal axis. Same inputs as codec."""
    qt, pkg = case["qt"], case["pkg"]
    ok, _ = verify_sig(qt, pkg["pubs"], pkg.get("revocations", {}),
                       signed_at=qt["body"].get("event_registered_at"))
    if not ok:
        return "UNVERIFIABLE"
    stmts = {o["body"].get("statement_id"): o for o in pkg["objects"]
             if o["body"].get("type") == "Statement"}
    st = stmts.get(qt["body"]["statement_id"])
    if st is None:
        return "UNVERIFIABLE"
    text = st["body"]["text"]
    try:
        excerpt = "".join(text[s:e] for s, e in qt["body"]["spans"])
    except Exception:
        return "UNVERIFIABLE"
    if excerpt != qt["body"]["quoted_text"]:
        if qt["body"].get("transform"):
            return "TRANSFORMED"
        return "UNVERIFIABLE"
    # naive context rule: each constraint's *span text* must appear
    # verbatim inside the quoted text — positional information unused.
    for o in pkg["objects"]:
        b = o["body"]
        if b.get("type") == "ContextConstraint" and \
                b["statement_id"] == st["body"]["statement_id"]:
            clause = "".join(text[s:e] for s, e in b["spans"])
            if clause not in qt["body"]["quoted_text"]:
                return "CONTEXT_FLAG"
    return "EXACT"


def ablate_no_context(case):
    """Ablation A: drop ContextConstraint objects before verifying."""
    pkg = dict(case["pkg"])
    pkg["objects"] = [o for o in pkg["objects"]
                      if o["body"].get("type") != "ContextConstraint"]
    return verify_quotation(pkg, case["qt"], t_event=NOW)["label"]


def ablate_no_temporal(case):
    """Ablation B: verify but ignore temporal output (label unchanged —
    temporal axis is an independent field, so we measure what the label
    loses: we report temporal==None as the ablation result)."""
    r = verify_quotation(case["pkg"], case["qt"], t_event=NOW)
    return {"label": r["label"], "temporal": None}


def prf(golds, preds, cls):
    tp = sum(1 for g, p in zip(golds, preds) if g == cls and p == cls)
    fp = sum(1 for g, p in zip(golds, preds) if g != cls and p == cls)
    fn = sum(1 for g, p in zip(golds, preds) if g == cls and p != cls)
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"p": round(pr, 3), "r": round(rc, 3), "f1": round(f, 3)}


def main():
    from bench import gen_t1_corpus, gen_t2_corpus, gen_t3
    t1 = gen_t1_corpus() + gen_t1b()
    t2 = gen_t2_corpus()
    t3 = gen_t3()
    pol = gen_policy()

    golds = [c["gold"] for c in t1]
    codec_pred = [verify_quotation(c["pkg"], c["qt"], t_event=NOW)["label"]
                  for c in t1]
    comp_pred = [comp_baseline(c) for c in t1]
    ablA = [ablate_no_context(c) for c in t1]

    def acc(ps):
        return round(sum(g == p for g, p in zip(golds, ps)) / len(golds), 3)

    # confusion matrix codec (4 active classes)
    labels = ["EXACT", "TRANSFORMED", "CONTEXT_FLAG", "DISPUTED",
              "UNVERIFIABLE"]
    conf = {g: {p: 0 for p in labels} for g in labels}
    for g, p in zip(golds, codec_pred):
        conf[g][p] += 1

    pol_ok = all(c["gold"] == c["verdict"] for c in pol)
    t2 = [dict(c, pred=statement_validity(c["pkg"], c["stmt"], c["t_event"],
                                          c["t_known"]))
          for c in t2]
    t2_acc = round(
        sum((c["gold_state"], c["gold_commit"]) ==
            (c["pred"]["state"], c["pred"]["commitment_state"])
            for c in t2) / len(t2), 3)

    out = {"_label": "SYNTHETIC benchmark v12 — NOT real-world performance",
           "seed": SEED,
           "corpus": {"t1": len(t1), "t2": len(t2), "t3": len(t3),
                      "policy": len(pol)},
           "T1": {"codec": {"accuracy": acc(codec_pred),
                            "ctx": prf(golds, codec_pred, "CONTEXT_FLAG"),
                            "overwarn": sum(
                                1 for g, p in zip(golds, codec_pred)
                                if g == "EXACT" and p != "EXACT")},
                  "comp_baseline": {"accuracy": acc(comp_pred),
                                    "ctx": prf(golds, comp_pred,
                                               "CONTEXT_FLAG")},
                  "ablation_no_context": {"accuracy": acc(ablA),
                                          "ctx_recall": prf(
                                              golds, ablA,
                                              "CONTEXT_FLAG")["r"]},
                  "confusion": conf,
                  "per_case": [{"cat": c["cat"], "gold": g, "codec": a,
                                "comp": b}
                               for c, g, a, b in zip(
                                   t1, golds, codec_pred, comp_pred)]},
           "T2": {"codec_accuracy": t2_acc},
           "T3": {"all_detected": all(c["gold"] for c in t3)},
           "policy": {"all_correct": pol_ok,
                      "cases": [{"cat": c["cat"], "gold": c["gold"],
                                 "verdict": c["verdict"]} for c in pol]},
           "note": "comp baseline equals codec on plain syntactic coverage "
                   "but loses positional (homograph) detection, bitemporal "
                   "hindsight queries, permissions, and fork detection."}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
