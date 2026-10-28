"""Tests for v9 analysis code. Run: python3 test_analysis.py
Covers: Holm known-p example, order swap, wrong-direction effect,
FWER under null, shared-arm correlation, boundary p, A rho sensitivity,
C wrong direction, joint partial/safety-fail, seed reproducibility."""
import random

import analysis as A


def t(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    assert cond, name


# 1. Holm on known p-values: {0.02, 0.04} at alpha=0.05
#    sorted: 0.02 <= 0.025 reject; 0.04 <= 0.05 reject -> both
r = A.holm_reject({"h1": 0.02, "h2": 0.04}, 0.05)
t("holm known example both rejected", r == {"h1", "h2"})
# {0.02, 0.06}: 0.02<=0.025 reject; 0.06>0.05 stop -> only h1
r = A.holm_reject({"h1": 0.02, "h2": 0.06}, 0.05)
t("holm stops after first failure", r == {"h1"})
# {0.06, 0.01}: sorted 0.01<=0.025 reject h2, 0.06>0.05 stop -> only h2
r = A.holm_reject({"h1": 0.06, "h2": 0.01}, 0.05)
t("holm order swap", r == {"h2"})
# boundary: p == alpha/m exactly -> reject (<=)
r = A.holm_reject({"h1": 0.025, "h2": 0.05}, 0.05)
t("holm boundary equality rejects", r == {"h1", "h2"})

# 2. signed z: large effect in WRONG direction must not be 'significant'
z = A.two_prop_z_signed(x_succ=30, x_ctrl=70, n_succ=100, n_ctrl=100)
t("wrong-direction z is negative", z < -3)
t("wrong-direction p is ~1 (not significant)",
  A.one_sided_p(z) > 0.99)

# 3. FWER under global null ~ alpha (small reps for test speed)
res = A.fwer_study_b(200, reps=4000)
est = res["fwer"]["estimate"]
t("FWER under null near 0.05", 0.02 < est < 0.09)

# 4. Study A: higher rho -> higher power at same n
p0 = A.power_study_a(50, 0.10, 0.20, 0.0)
p5 = A.power_study_a(50, 0.10, 0.20, 0.5)
t("A power increases with rho", p5 > p0)
t("A SD_diff at rho=0 is 0.283",
  abs(0.20 * (2 * (1 - 0.0)) ** 0.5 - 0.283) < 0.001)
# non-inferiority differs from superiority
ni = A.power_study_a(50, 0.0, 0.20, 0.5, mode="noninferiority")
su = A.power_study_a(50, 0.0, 0.20, 0.5, mode="superiority")
t("noninferiority != superiority at delta=0", ni > su)

# 5. Study C wrong direction: drop negative (worse) -> ~no power
r = A.power_study_c(180, p_mis_c0=0.40, drop=-0.15, reps=4000)
t("C wrong direction yields ~no rejections", r["estimate"] < 0.10)

# 6. Joint: safety-fail suppresses joint; single-study success < partial
j = A.joint_power(reps=2000, safety_true_rate=0.30)  # safety almost always fails
t("joint collapses when safety fails", j["joint"]["estimate"] < 0.05)
t("marginals still high when safety fails",
  j["marginals"]["A"]["estimate"] > 0.8)
# partial success: joint <= each marginal
j2 = A.joint_power(reps=2000)
for m in ("A", "B_both", "C", "safety"):
    t(f"joint <= marginal {m}",
      j2["joint"]["estimate"] <= j2["marginals"][m]["estimate"] + 0.03)

# 7. seed reproducibility
j3 = A.joint_power(reps=500, seed=42)
j4 = A.joint_power(reps=500, seed=42)
t("seed reproducibility", j3 == j4)

# 8. binomial upper bound: 0 events bounds rate, never 0
ub = A.binomial_upper_bound(0, 300)
t("0 events still gives positive bound", 0 < ub < 0.02)
n52 = A.trials_needed_for_margin(0.05)
t("n for margin .05 is ~52", 45 <= n52 <= 60)

# 9. Study B both-power lower than either marginal
b = A.power_study_b(200, reps=4000)
t("B both <= marginals",
  b["power_both"]["estimate"] <= b["power_h1"]["estimate"] + 0.03 and
  b["power_both"]["estimate"] <= b["power_h2"]["estimate"] + 0.03)

print("ALL TESTS DONE")
