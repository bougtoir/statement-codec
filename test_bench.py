"""Sanity tests for the Paper-1 benchmark. Run: python3 test_bench.py"""
import json
import subprocess
import sys

out = subprocess.run([sys.executable, "bench.py"], capture_output=True,
                     text=True)
d = json.loads(out.stdout)


def t(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    assert cond, name


t("corpus sizes", d["corpus"] == {"t1": 13, "t2": 9, "t3": 1})
t("codec T1 accuracy 1.0 on synthetic corpus",
  d["T1_codec"]["micro_accuracy"] == 1.0)
t("over-warning zero on legitimate quotes",
  d["T1_codec"]["over_warning_on_legit"] == 0)
t("baselines strictly worse",
  all(v["micro_accuracy"] < 1.0
      for v in d["T1_baselines"].values()))
t("baselines miss all context drops",
  all(v["context_flag"]["recall"] == 0.0
      for v in d["T1_baselines"].values()))
t("T2 temporal 1.0", d["T2_temporal"]["codec_accuracy"] == 1.0)
t("T3 all detected", d["T3_integrity"]["all_detected"] is True)
t("synthetic label present",
  "SYNTHETIC" in d["_label"])

# reproducibility of RESULTS (key material is freshly generated per run —
# Ed25519 keys are random — so only scores/labels must be identical)
out2 = subprocess.run([sys.executable, "bench.py"], capture_output=True,
                      text=True)
d2 = json.loads(out2.stdout)
for k in ("T1_codec", "T1_baselines", "T2_temporal", "T3_integrity",
          "corpus", "seed"):
    t(f"result reproducibility: {k}",
      json.dumps(d2[k], sort_keys=True) == json.dumps(d[k], sort_keys=True))
print("ALL BENCH TESTS DONE")
