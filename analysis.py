"""v9 analysis code — corrected Holm, signed tests, rebuilt joint gate.

SYNTHETIC ONLY. All outputs are assumption-based planning simulations used
to justify pre-registration numbers; they are NOT study results. Seeds fixed.
Stdlib only (statistics.NormalDist for exact normal CDF/quantiles — no
hardcoded 1.645/1.960 in test logic).

v8 -> v9 corrections implemented here
--------------------------------------
1. Holm step-down: v8 used z > 1.645/2 then z > 1.645 (wrong — it halved the
   z threshold instead of the alpha). Correct: sort one-sided p-values
   ascending; p_(1) <= alpha/2 (=0.025), p_(2) <= alpha (=0.05). Equality is
   a rejection (<=). In z-space the first threshold is
   inv_norm(1 - 0.025) = 1.960, the second inv_norm(1 - 0.05) = 1.645.
2. two_prop_z returned |difference|, which made large effects in the WRONG
   direction count as success. Now all tests use signed statistics and
   one-sided p-values computed directly.
3. Study B shares group B2 across both hypotheses (H1: B2>B1, H2: B3>B2),
   so the two z statistics are negatively correlated (~ -1/2 at equal n).
   v8 treated them as independent. The simulation now generates each arm's
   count once per replicate and computes both statistics from the same
   counts, so the correlation is produced by the design, not assumed.
4. joint_power() is rebuilt: each replicate generates A/B/C data, applies
   the pre-specified analyses (paired t approx for A; Holm on signed z for
   B, requiring BOTH hypotheses; signed z for C; binomial upper bound for
   the source-ID safety gate) and ANDs them. rho_A (within-subject corr in
   study A) and rho_joint (cross-study shared factor) are distinct
   parameters; several dependence structures are simulated.
5. Safety gate: '0 source-ID events' is not proof of safety. We use a
   one-sided upper binomial confidence bound vs a pre-set margin and report
   the number of trials needed for the bound to fall below the margin.
6. Monte Carlo error: every simulated probability reports
   phat +/- 1.96*sqrt(phat(1-phat)/reps).
"""

import json
import math
import random
import sys
from statistics import NormalDist

ND = NormalDist()
SEED = 20261010


def norm_cdf(z):
    return ND.cdf(z)


def inv_norm(p):
    return ND.inv_cdf(p)


def one_sided_p(z):
    """P(Z >= z) under the standard normal — the one-sided p-value."""
    return 1.0 - ND.cdf(z)


def mc_interval(phat, reps):
    """95% Monte Carlo interval for a simulated probability."""
    se = math.sqrt(phat * (1 - phat) / reps)
    return {"estimate": round(phat, 4),
            "mc_se": round(se, 4),
            "mc_ci95": [round(max(0.0, phat - 1.96 * se), 4),
                        round(min(1.0, phat + 1.96 * se), 4)]}


# ----------------------------------------------------------------------
# Generic Holm step-down on one-sided p-values
# ----------------------------------------------------------------------

def holm_reject(pvals, alpha=0.05):
    """Holm procedure over a family of one-sided hypotheses.

    pvals: dict {name: p-value}. Returns the set of rejected names.
    Sort ascending; p_(i) <= alpha/(m - i + 1) for i=1..m, stop at first
    failure. Equality counts as rejection (<=).
    """
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    rejected = set()
    for i, (name, p) in enumerate(items):
        if p <= alpha / (m - i):
            rejected.add(name)
        else:
            break
    return rejected


# ----------------------------------------------------------------------
# Signed two-proportion z statistic
# ----------------------------------------------------------------------

def two_prop_z_signed(x_succ, x_ctrl, n_succ, n_ctrl):
    """Signed z for H: p_succ > p_ctrl (direction matters).

    se = sqrt(pbar(1-pbar)(1/n_succ + 1/n_ctrl)) with pooled pbar.
    Positive z supports the stated direction; a large negative z is a
    large effect in the WRONG direction and must not count as success.
    """
    pbar = (x_succ + x_ctrl) / (n_succ + n_ctrl)
    se = math.sqrt(pbar * (1 - pbar) * (1 / n_succ + 1 / n_ctrl))
    if se == 0:
        return 0.0
    return (x_succ / n_succ - x_ctrl / n_ctrl) / se


# ----------------------------------------------------------------------
# Study A — paired within-subject contrast (superiority + non-inferiority)
# ----------------------------------------------------------------------

def power_study_a(n, delta, sigma_w, rho, alpha=0.05, mode="superiority"):
    """Analytic power for the A3-A0 paired contrast.

    delta: true mean difference. sigma_w: per-condition error SD.
    rho: within-subject correlation between conditions.
    SD_diff = sigma_w * sqrt(2(1-rho)).

    mode='superiority': H1 delta > 0, one-sided alpha.
    mode='noninferiority': H1 delta > -margin, tested against
        margin = -sesoi (i.e. we show deterioration < sesoi), one-sided
        alpha. These are DIFFERENT hypotheses with different success
        rules; a superiority success is never relabelled non-inferiority
        and vice versa.
    """
    sd_diff = sigma_w * math.sqrt(2 * (1 - rho))
    se = sd_diff / math.sqrt(n)
    za = inv_norm(1 - alpha)
    if mode == "superiority":
        ncp = delta / se
        return 1 - norm_cdf(za - ncp)
    if mode == "noninferiority":
        # reject H0: delta <= -sesoi  (test statistic vs boundary -sesoi)
        sesoi = 0.10
        ncp = (delta + sesoi) / se
        return 1 - norm_cdf(za - ncp)
    raise ValueError(mode)


def report_a():
    sup = []
    for rho in (0.0, 0.3, 0.5, 0.7):
        for n in (30, 50, 70, 90, 120):
            sup.append({"rho": rho, "n": n,
                        "power_superiority": round(
                            power_study_a(n, 0.10, 0.20, rho), 3),
                        "power_noninferiority_at_delta0": round(
                            power_study_a(n, 0.0, 0.20, rho,
                                          mode="noninferiority"), 3),
                        "sd_diff": round(0.20 * math.sqrt(2 * (1 - rho)), 3)})
    return {
        "design": "paired within-subject A3-A0 contrast",
        "sesoi": 0.10, "sigma_w": 0.20, "alpha": 0.05,
        "model": "SD_diff = sigma_w*sqrt(2(1-rho)); rho=0 -> 0.283",
        "hypotheses": {
            "primary_superiority": "H1: delta(A3-A0) > 0, one-sided a=.05",
            "safety_noninferiority": "H1: delta > -0.10 (non-inferiority "
                                     "margin), one-sided a=.05; a "
                                     "DIFFERENT hypothesis from the "
                                     "primary — never interchanged"},
        "sims": sup,
        "recommend": "n=90 covers worst case rho=0 (power .92 sup). "
                     "If rho>=0.5 (plausible, same speaker), n=50-70 "
                     "suffices; sensitivity grid retained."}


# ----------------------------------------------------------------------
# Study B — Holm over {H1: B2>B1, H2: B3>B2}, shared B2 arm
# ----------------------------------------------------------------------

def power_study_b(n, base=0.55, lift=0.15, alpha=0.05, reps=20000,
                  shared_b2=True, seed=None):
    """Simulate Study B.

    Arms B1,B2,B3 each size n with true rates base, base+lift, base+2*lift.
    H1: B2>B1 ; H2: B3>B2. With shared_b2=True the SAME simulated B2 count
    enters both z statistics (protocol's shared-group design) -> the two
    statistics are negatively correlated; we do NOT assume independence.
    With shared_b2=False an independent second B2 draw is used for H2
    (sensitivity scenario).

    Returns marginal power per hypothesis, P(both rejected) — the
    confirmatory success rule — P(at least one), and MC intervals.
    """
    rng = random.Random(SEED if seed is None else seed)
    h1 = h2 = both = any_ = 0
    for _ in range(reps):
        x1 = sum(1 for _ in range(n) if rng.random() < base)
        x2 = sum(1 for _ in range(n) if rng.random() < base + lift)
        x3 = sum(1 for _ in range(n) if rng.random() < base + 2 * lift)
        z1 = two_prop_z_signed(x2, x1, n, n)          # B2 vs B1, direction B2>B1
        if shared_b2:
            x2b = x2                                # shared arm: same draw
        else:
            x2b = sum(1 for _ in range(n) if rng.random() < base + lift)
        z2 = two_prop_z_signed(x3, x2b, n, n)         # B3 vs B2, direction B3>B2
        p1 = one_sided_p(z1)
        p2 = one_sided_p(z2)
        rej = holm_reject({"h1": p1, "h2": p2}, alpha=alpha)
        h1 += "h1" in rej
        h2 += "h2" in rej
        both += len(rej) == 2
        any_ += len(rej) >= 1
    return {"n_per_group": n, "reps": reps, "shared_b2": shared_b2,
            "multiplicity": "Holm FWER, one-sided family alpha=0.05 "
                            "(p_(1)<=0.025 then p_(2)<=0.05)",
            "power_h1": mc_interval(h1 / reps, reps),
            "power_h2": mc_interval(h2 / reps, reps),
            "power_both": mc_interval(both / reps, reps),
            "power_any": mc_interval(any_ / reps, reps)}


def fwer_study_b(n, base=0.55, alpha=0.05, reps=20000):
    """FWER check under the global null (all arms at base rate).
    Holm should keep P(any rejection) <= alpha + MC error."""
    rng = random.Random(SEED + 7)
    any_ = 0
    for _ in range(reps):
        x1 = sum(1 for _ in range(n) if rng.random() < base)
        x2 = sum(1 for _ in range(n) if rng.random() < base)
        x3 = sum(1 for _ in range(n) if rng.random() < base)
        p1 = one_sided_p(two_prop_z_signed(x2, x1, n, n))
        p2 = one_sided_p(two_prop_z_signed(x3, x2, n, n))
        rej = holm_reject({"h1": p1, "h2": p2}, alpha=alpha)
        any_ += len(rej) >= 1
    return {"n": n, "reps": reps, "fwer": mc_interval(any_ / reps, reps),
            "nominal_alpha": alpha}


def report_b():
    return {
        "family": "{H1: B2>B1 on Q2, H2: B3>B2 on Q2} — confirmatory",
        "shared_arm": "B2 appears in both hypotheses -> statistics are "
                      "correlated by design (simulated, not assumed)",
        "scenarios": {str(n): power_study_b(n)
                      for n in (200, 250, 300, 400)},
        "no_shared_arm_sensitivity": {str(n): power_study_b(
            n, shared_b2=False, seed=SEED + 5) for n in (200, 250)},
        "fwer_check": fwer_study_b(200),
    }


# ----------------------------------------------------------------------
# Study C — misinterpretation rate, signed test, separate safety estimands
# ----------------------------------------------------------------------

def power_study_c(n, p_mis_c0=0.40, drop=0.15, alpha=0.05, reps=20000):
    """H1: p_mis(C2) < p_mis(C0). Signed z on (p_C0 - p_C2); one-sided.
    FP (legitimate critical quote over-warned) and FN (missed distortion)
    are SEPARATE estimands planned in the SAP, not part of this power
    calculation; chilling-effect metrics (submission rate of critical
    quotes, adoption rate, editing time) are likewise separate."""
    rng = random.Random(SEED + 11)
    hits = 0
    for _ in range(reps):
        x0 = sum(1 for _ in range(n) if rng.random() < p_mis_c0)
        x2 = sum(1 for _ in range(n) if rng.random() < p_mis_c0 - drop)
        z = two_prop_z_signed(x0, x2, n, n)  # direction: C0 > C2
        if one_sided_p(z) <= alpha:
            hits += 1
    return mc_interval(hits / reps, reps)


def report_c():
    return {"hypothesis": "H1: p_mis(C2) < p_mis(C0), one-sided a=.05",
            "separate_estimands": ["FP rate on legitimate critical quotes",
                                   "FN rate on distorted quotes",
                                   "chilling: submission/adoption/edit-time"],
            "scenarios": {str(n): power_study_c(n)
                          for n in (120, 150, 180, 220)}}


# ----------------------------------------------------------------------
# Safety gate — source-identification events
# ----------------------------------------------------------------------

def binomial_upper_bound(x, n, alpha=0.05):
    """One-sided upper confidence bound for a binomial rate
    (Wilson score upper limit). For x=0 this gives ~ 1 - alpha**(1/n)
    (rule-of-three analogue: ~3/n at alpha=0.05)."""
    if n == 0:
        return 1.0
    z = inv_norm(1 - alpha)
    phat = x / n
    denom = 1 + z * z / n
    center = phat + z * z / (2 * n)
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return (center + half) / denom


def trials_needed_for_margin(margin, alpha=0.05, max_n=100000):
    """Smallest n such that observing 0 events yields an upper bound
    <= margin. Reports that '0 events' only bounds the rate; it never
    proves the rate is 0."""
    for n in range(1, max_n):
        if binomial_upper_bound(0, n, alpha) <= margin:
            return n
    return None


def report_safety():
    rows = {}
    for margin in (0.05, 0.10, 0.20, 0.30):
        n_need = trials_needed_for_margin(margin)
        rows[f"margin={margin}"] = {
            "n_needed_if_0_events": n_need,
            "upper_bound_at_0_in_that_n": round(
                binomial_upper_bound(0, n_need), 4)}
    return {"rule": "source-ID safety gate passes iff one-sided upper "
                    "95% bound on the identification rate <= pre-set "
                    "margin. '0 observed events' bounds but does not "
                    "prove safety; margins 0.10-0.30 are PROVISIONAL "
                    "(normative, not empirical) — sensitivity shown.",
            "chilling_estimands": ["critical-quote submission rate",
                                   "legitimate-quote adoption rate",
                                   "editing/verification time"],
            "scenarios": rows}


# ----------------------------------------------------------------------
# Joint gate — rebuilt: per-replicate data -> pre-specified analyses -> AND
# ----------------------------------------------------------------------

def _draw_study_a(rng, n, delta, sigma_w, rho, g, w):
    """Return z for the paired contrast.

    rho is the WITHIN-SUBJECT correlation (affects SD_diff -> ncp).
    w*g is the cross-study shared-factor loading (affects correlation
    ACROSS studies). rho_A and rho_joint are different parameters and
    must not be conflated.
    """
    sd_diff = sigma_w * math.sqrt(2 * (1 - rho))
    ncp = delta / (sd_diff / math.sqrt(n))
    return ncp + w * g + math.sqrt(max(0.0, 1 - w * w)) * rng.gauss(0, 1)


def _draw_study_b(rng, n, base, lift, g, w):
    """Draw B arm counts (shared B2 across both contrasts) and return the
    two one-sided p-values. The within-B correlation comes from sharing
    x2; the cross-study correlation from w*g injected into each arm's
    success probability via a normal-shifted latent threshold."""
    # latent-normal representation keeps the factor model consistent:
    # each arm's respondent count = # latents below threshold.
    def arm(rate):
        # per-person latent = rate-shifted; shared g shifts the arm mean
        t = inv_norm(rate)
        return sum(1 for _ in range(n)
                   if rng.gauss(0, 1) - w * g / math.sqrt(1 - w * w + 1e-12)
                   < t)
    x1 = arm(base)
    x2 = arm(base + lift)   # one draw, used in BOTH contrasts
    x3 = arm(base + 2 * lift)
    p1 = one_sided_p(two_prop_z_signed(x2, x1, n, n))
    p2 = one_sided_p(two_prop_z_signed(x3, x2, n, n))
    return p1, p2


def _draw_study_c(rng, n, p_mis_c0, drop, g, w):
    def arm(rate):
        t = inv_norm(rate)
        return sum(1 for _ in range(n)
                   if rng.gauss(0, 1) - w * g / math.sqrt(1 - w * w + 1e-12)
                   < t)
    x0 = arm(p_mis_c0)
    x2 = arm(p_mis_c0 - drop)
    return one_sided_p(two_prop_z_signed(x0, x2, n, n))


def _draw_safety(rng, n_trials, true_rate, margin, alpha=0.05):
    """Safety gate replicate: draw #source-ID events, pass iff the
    one-sided upper bound <= margin. Statistical decision vs true rate
    are kept distinct: true_rate is an ASSUMPTION of the scenario."""
    x = sum(1 for _ in range(n_trials) if rng.random() < true_rate)
    return binomial_upper_bound(x, n_trials, alpha) <= margin, x


def joint_power(n_a=90, n_b=250, n_c=180, rho_A=0.0, rho_joint=0.0,
                safety_n=600, safety_true_rate=0.02, safety_margin=0.05,
                reps=20000, seed=None, alpha=0.05):
    """Joint success = A sup. reject AND B both-hypotheses reject AND
    C reject AND safety gate pass.

    rho_joint enters through w = sqrt(rho_joint) on the shared factor g.
    rho_A is independent of rho_joint and only affects study A's ncp.
    """
    rng = random.Random(SEED + 13 if seed is None else seed)
    w = math.sqrt(rho_joint)
    za = inv_norm(1 - alpha)
    hits = a_ok = b_ok = c_ok = s_ok = 0
    for _ in range(reps):
        g = rng.gauss(0, 1)
        zA = _draw_study_a(rng, n_a, 0.10, 0.20, rho_A, g, w)
        okA = one_sided_p(zA) <= alpha  # superiority, one-sided
        p1, p2 = _draw_study_b(rng, n_b, 0.55, 0.15, g, w)
        okB = len(holm_reject({"h1": p1, "h2": p2}, alpha)) == 2
        pC = _draw_study_c(rng, n_c, 0.40, 0.15, g, w)
        okC = pC <= alpha
        okS, _x = _draw_safety(rng, safety_n, safety_true_rate,
                               safety_margin, alpha)
        a_ok += okA; b_ok += okB; c_ok += okC; s_ok += okS
        hits += okA and okB and okC and okS
    return {"n": {"A": n_a, "B": n_b, "C": n_c},
            "rho_A": rho_A, "rho_joint": rho_joint,
            "safety": {"n": safety_n, "assumed_true_rate": safety_true_rate,
                       "margin": safety_margin},
            "reps": reps,
            "marginals": {"A": mc_interval(a_ok / reps, reps),
                          "B_both": mc_interval(b_ok / reps, reps),
                          "C": mc_interval(c_ok / reps, reps),
                          "safety": mc_interval(s_ok / reps, reps)},
            "joint": mc_interval(hits / reps, reps)}


def report_joint():
    # v10: primary safety margin unified to 0.05 (source-identification
    # severity rationale — NOT loosened for power). Instead safety_n
    # raised 300 -> 600 so the upper bound can clear the strict margin.
    scenarios = {}
    for r in (0.0, 0.2, 0.4):
        scenarios[f"rho_joint={r}"] = joint_power(rho_joint=r)
    scenarios["safety_n=300_v9setting"] = joint_power(safety_n=300)
    scenarios["safety_n=1000"] = joint_power(safety_n=1000)
    scenarios["fully_shared_subjects_rho=1"] = joint_power(rho_joint=0.9)
    scenarios["larger_n"] = joint_power(n_a=120, n_b=300, n_c=220)
    scenarios["worse_safety_rate_5pct"] = joint_power(safety_true_rate=0.05)
    scenarios["rho_A_0.5"] = joint_power(rho_A=0.5)
    # independence illustration: product of marginals vs simulated
    indep = joint_power(rho_joint=0.0)
    m = indep["marginals"]
    prod = (m["A"]["estimate"] * m["B_both"]["estimate"] *
            m["C"]["estimate"] * m["safety"]["estimate"])
    return {"definition": "joint = A AND (B h1 AND B h2) AND C AND safety",
            "note": "rho_A (within-A) and rho_joint (cross-study) are "
                    "distinct. Product-of-marginals is the independence "
                    "ILLUSTRATION ONLY, not a general formula.",
            "independence_product_illustration": round(prod, 4),
            "target": ">= 0.80 joint (illustrative; v7 used 0.85^3=0.614 "
                      "as the naive independent product)",
            "scenarios": scenarios}


def main():
    out = {"_label": "SYNTHETIC planning simulation — NOT study results",
           "seed": SEED,
           "study_a": report_a(),
           "study_b": report_b(),
           "study_c": report_c(),
           "safety_gate": report_safety(),
           "joint_gate": report_joint()}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
