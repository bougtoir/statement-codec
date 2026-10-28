"""Sanity tests for v12 benchmark. Run: python3 test_bench_v12.py"""
import json, subprocess, sys
out = subprocess.run([sys.executable, "bench_v12.py"], capture_output=True, text=True)
d = json.loads(out.stdout)
def t(n, c):
    print(("PASS " if c else "FAIL ") + n); assert c, n
t("T1 codec all correct", d["T1"]["codec"]["accuracy"] == 1.0)
t("T1 over-warning 0", d["T1"]["codec"]["overwarn"] == 0)
t("comp baseline strictly weaker", d["T1"]["comp_baseline"]["accuracy"] < 1.0)
t("comp misses homograph", any(c["cat"]=="homograph_clause" and c["comp"]=="EXACT" and c["codec"]=="CONTEXT_FLAG" for c in d["T1"]["per_case"]))
t("ablation A collapses ctx recall", d["T1"]["ablation_no_context"]["ctx_recall"] == 0.0)
t("T2 1.0", d["T2"]["codec_accuracy"] == 1.0)
t("T3 detected", d["T3"]["all_detected"])
t("policy correct", d["policy"]["all_correct"])
t("SYNTHETIC label", "SYNTHETIC" in d["_label"])
out2 = subprocess.run([sys.executable,"bench_v12.py"],capture_output=True,text=True)
d2 = json.loads(out2.stdout)
t("reproducible results", json.dumps({k:d[k] for k in ("T1","T2","T3","policy")},sort_keys=True)==json.dumps({k:d2[k] for k in ("T1","T2","T3","policy")},sort_keys=True))
print("ALL V12 BENCH TESTS DONE")
