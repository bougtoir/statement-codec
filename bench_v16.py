"""v16: feature-parity baseline (comp2). Independent decision code over the same
primitives (verify_sig, canon, sha256, _authorized_amendment). Same inputs,
signed span-position constraints, bitemporal state, authorization, audit —
the feature-parity comparator. Reports label-level equivalence + complexity."""
import json, sys, unicodedata, inspect
sys.path.insert(0, ".")
from codec import (verify_sig, verify_quotation, statement_validity, canon,
                   sha256, _authorized_amendment)
import bench_v12
from bench import gen_t1_corpus, gen_t2_corpus
NOW = "2026-01-01T00:00:00+00:00"

def _positions(spans):
    s = set()
    for a, b in spans: s.update(range(a, b))
    return s

def comp2_label(case):
    """Independent implementation of the same verification contract."""
    qt, pkg = case["qt"], case["pkg"]
    ok, _ = verify_sig(qt, pkg["pubs"], pkg.get("revocations", {}),
                       signed_at=qt["body"].get("event_registered_at"))
    if not ok: return "UNVERIFIABLE"
    stmts = {o["body"].get("statement_id"): o for o in pkg["objects"]
             if o["body"].get("type") == "Statement"}
    st = stmts.get(qt["body"]["statement_id"])
    if st is None or sha256(canon(st)) != qt["body"]["statement_hash"]:
        return "UNVERIFIABLE"
    text = unicodedata.normalize("NFC", st["body"]["text"])
    spans = qt["body"]["spans"]
    if any(a < 0 or b > len(text) or a > b for a, b in spans):
        return "UNVERIFIABLE"   # MISMATCH maps to UNVERIFIABLE label
    excerpt = "".join(text[a:b] for a, b in spans)
    qt_text = unicodedata.normalize("NFC", qt["body"]["quoted_text"])
    if excerpt != qt_text:
        if qt["body"].get("transform") and excerpt.replace(" ", "") == qt_text.replace(" ", ""):
            tm = "TRANSFORMED"
        elif qt["body"].get("transform"):
            tm = "TRANSFORMED"
        else:
            return "UNVERIFIABLE"
    else:
        tm = "EXACT"
    # dispute?
    tid = qt["body"]["statement_id"]
    disputed = any(o["body"].get("type") == "Amendment" and o["body"]["kind"] == "dispute"
                   and o["body"]["target_id"] in (tid, qt["body"].get("quote_id"))
                   and _authorized_amendment(pkg, o, st["body"].get("speaker_keyid", ""))
                   for o in pkg.get("objects", []))
    # positional context coverage via position-set difference (different algo)
    ctx_missing = False
    for o in pkg["objects"]:
        b = o["body"]
        if b.get("type") == "ContextConstraint" and b["statement_id"] == tid:
            need = _positions(b["spans"]); have = _positions(spans)
            if need - have: ctx_missing = True
    if disputed: return "DISPUTED"
    if ctx_missing: return "CONTEXT_FLAG"
    return "TRANSFORMED" if tm == "TRANSFORMED" else "EXACT"

res = {"_label": "SYNTHETIC parity comparison (comp2 vs codec)",
       "T1": [], "equivalent_labels": True}
t1 = gen_t1_corpus() + bench_v12.gen_t1b()
for c in t1:
    a = verify_quotation(c["pkg"], c["qt"], t_event=NOW)["label"]
    b = comp2_label(c)
    same = a == b
    res["T1"].append({"cat": c["cat"], "codec": a, "comp2": b, "same": same})
    if not same: res["equivalent_labels"] = False
res["codec_label_loc"] = len(inspect.getsource(verify_quotation).splitlines())
res["comp2_label_loc"] = len(inspect.getsource(comp2_label).splitlines())
print(json.dumps(res, ensure_ascii=False, indent=1))
