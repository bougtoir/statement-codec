"""v5 evaluation harness — Study C technical evaluation + friction logging.

Generates synthetic interview packages, applies gold-labeled quotations,
scores coverage_detail precision/recall/F1 against human-set gold labels,
and emits an anonymized op-count/timing log (friction proxy).

Gold labels are manually assigned in the scenario table below; they are
NOT model-generated. The harness claims mechanical coverage detection
only — semantic faithfulness stays a separate, human judgment.
"""
import json
import sys
import time

sys.path.insert(0, ".")
from codec import (gen_key, key_id, make_amendment, make_consent_manifest,
                   make_context_constraint, make_quotation, make_statement,
                   coverage_detail, verify_quotation, verify_sig)

NOW = "2026-10-10T04:30:00Z"
DEFV = dict(valid_from="2026-10-10T00:00:00Z",
            valid_until="2026-12-31T00:00:00Z")


def build_case(st_text, constraint_spans, quote_spans, quote_text, *,
               statement_type="speech", kind="conditional",
               transforms=None, t_event=NOW, extra=None):
    """One eval case -> dict with gold fields filled in by caller."""
    speaker, recorder = gen_key(), gen_key()
    sk, rk = key_id(speaker.public_key()), key_id(recorder.public_key())
    manifest = make_consent_manifest(
        [speaker, recorder], "eval",
        parties=[{"keyid": sk, "role": "speaker", "disclosure": "real_name"},
                 {"keyid": rk, "role": "recorder", "disclosure": "real_name"}],
        terms={"recording": True, "direct_quote": True, "paraphrase": True},
        effective_at="2026-10-01T00:00:00Z")
    kw = dict(extra or {}); kw.update(DEFV)
    st = make_statement(speaker, "eval", st_text, NOW, NOW, NOW, [],
                        "on-record", statement_type=statement_type, **kw)
    cond = make_context_constraint(speaker, st["body"]["statement_id"],
                                   constraint_spans, kind, "cond", "speaker")
    qt = make_quotation(recorder, st, quote_spans, quote_text, "pub",
                        transform=transforms)
    pkg = {"objects": [manifest, st, cond],
           "pubs": {sk: speaker.public_key(), rk: recorder.public_key()},
           "revocations": {}}
    return pkg, qt


# --- synthetic interview snippets (no real private statements) ---
ST_COND = ("条件付きで言えば、来年度の予算案は凍結されるべきだと考えている。"
           "ただしこれは歳入見通しが下方修正された場合に限る。"
           "現時点では楽観している。")
I_COND = ST_COND.find("現時点では")

ST_NEG = "増税案は最終手段であり、第一に歳出改革を尽くすべきだ。安易な増税論には賛成しない。"
I_NEG = ST_NEG.find("安易な")

ST_QA = ("問: 辞任は考えますか。答: 現時点では考えていません。"
         "しかし職責を果たせないと判断すれば、その時点で明らかにします。")
I_QA = ST_QA.find("現時点では")

ST_TIME = ("この規制は2027年3月末までの暫定措置として妥当だ。"
           "恒久化については次のレビューで判断すべきだ。")
I_TIME = ST_TIME.find("恒久化")

ST_SARC = "ええ、その案がこのまま通れば素晴らしい結果になるでしょうね。問題が噴出するでしょうが。"


def scen(kind, gold_ctx, gold_label, *args, **kw):
    pkg, qt = build_case(*args, **kw)
    return {"kind": kind, "gold_context": gold_ctx,
            "gold_label": gold_label, "pkg": pkg, "qt": qt}


SCENARIOS = [
    # exact full quote incl. constraint span -> gold EXACT
    scen("exact_full", "FULL", "EXACT", ST_COND, [[0, I_COND]],
         [[0, len(ST_COND)]], ST_COND),
    # clip drops the conditional clause -> gold CONTEXT_FLAG (PARTIAL)
    scen("clip_condition", "MISSING", "CONTEXT_FLAG", ST_COND, [[0, I_COND]],
         [[I_COND, len(ST_COND)]], ST_COND[I_COND:]),
    # 1-char overlap must NOT pass (v0.1 bug regression)
    scen("one_char_overlap", "PARTIAL", "CONTEXT_FLAG", ST_COND,
         [[0, I_COND]], [[I_COND - 1, I_COND]], ST_COND[I_COND - 1:I_COND]),
    # half of constraint span covered -> PARTIAL
    scen("half_covered", "PARTIAL", "CONTEXT_FLAG", ST_COND, [[0, I_COND]],
         [[I_COND // 2, len(ST_COND)]], ST_COND[I_COND // 2:]),
    # negation clause omitted
    scen("clip_negation", "MISSING", "CONTEXT_FLAG", ST_NEG, [[I_NEG, len(ST_NEG)]],
         [[0, I_NEG]], ST_NEG[:I_NEG]),
    # Q&A: answer quoted without the question
    scen("qa_without_question", "MISSING", "CONTEXT_FLAG", ST_QA, [[0, I_QA]],
         [[I_QA, len(ST_QA)]], ST_QA[I_QA:]),
    # time-limited clause dropped
    scen("clip_time_limit", "MISSING", "CONTEXT_FLAG", ST_TIME, [[0, I_TIME]],
         [[I_TIME, len(ST_TIME)]], ST_TIME[I_TIME:]),
    # paraphrase that keeps constraint span -> TRANSFORMED (literal mismatch)
    scen("paraphrase_keep_context", "FULL", "TRANSFORMED", ST_COND, [[0, I_COND]],
         [[0, len(ST_COND)]], ST_COND.replace("楽観している", "楽観しているのだ"),
         transforms="paraphrase"),
    # sarcasm: mechanical check can't judge reversal -> honest UNVERIFIABLE-ish
    scen("sarcasm", "FULL", "EXACT", ST_SARC, [[0, 10]],
         [[0, len(ST_SARC)]], ST_SARC),
    # no constraints declared, exact quote -> EXACT (context not required)
    scen("no_constraint", "FULL", "EXACT", ST_COND, [],
         [[I_COND, len(ST_COND)]], ST_COND[I_COND:]),
    # multi-span constraint, only one covered -> PARTIAL
    scen("multi_span_partial", "MISSING", "CONTEXT_FLAG", ST_TIME,
         [[0, I_TIME], [I_TIME, len(ST_TIME)]],
         [[I_TIME, len(ST_TIME)]], ST_TIME[I_TIME:]),
]


def score():
    rows, events = [], []
    for s in SCENARIOS:
        t0 = time.time()
        r = verify_quotation(s["pkg"], s["qt"], t_event=NOW)
        pred_ctx = r["context"]["status"]
        pred_label = r["label"]
        ok_ctx = pred_ctx == s["gold_context"]
        ok_lab = pred_label == s["gold_label"]
        rows.append({"kind": s["kind"], "gold_context": s["gold_context"],
                     "pred_context": pred_ctx, "ctx_ok": ok_ctx,
                     "gold_label": s["gold_label"],
                     "pred_label": pred_label, "label_ok": ok_lab})
        events.append({"op": "verify_quotation", "ms": round(
            (time.time() - t0) * 1000, 2), "case": s["kind"]})

    tp = sum(1 for r in rows if r["gold_context"] != "FULL"
             and r["pred_context"] != "FULL")
    fp = sum(1 for r in rows if r["gold_context"] == "FULL"
             and r["pred_context"] != "FULL")
    fn = sum(1 for r in rows if r["gold_context"] != "FULL"
             and r["pred_context"] == "FULL")
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = (2 * prec * rec / (prec + rec)) if prec and rec else None
    return {"rows": rows,
            "metrics": {"tp": tp, "fp": fp, "fn": fn,
                        "precision": prec, "recall": rec, "f1": f1,
                        "n": len(rows)},
            "friction_log": events,
            "note": "mechanical coverage only; sarcasm/semantic reversal "
                    "is out of scope for automated context detection"}


def friction_demo():
    """4-condition interview flow simulation (Study A prep) — op counts only."""
    k = gen_key()
    ops = []
    def log(op, n): ops.append({"step": op, "ops": n})
    log("A0: record -> write article", 2)
    log("A1: record -> sign statement -> archive", 3)
    log("A2: A1 + declare constraints -> verify quote", 5)
    log("A3: A2 + consent manifest multi-sig -> set horizons", 8)
    return {"conditions": ops,
            "note": "op-count model only; real wall-clock friction needs "
                    "field pilot"}


if __name__ == "__main__":
    out = score()
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(json.dumps(friction_demo(), ensure_ascii=False, indent=2))
