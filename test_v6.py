"""v6 tests: adversarial field scenarios + eval harness integrity."""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from codec import (check_use, coverage_detail, detect_fork, gen_key, key_id,
                   make_amendment, make_consent_manifest,
                   make_context_constraint, make_quotation, make_statement,
                   make_validity_event, verify_quotation, verify_sig,
                   AuditLog)
from eval import SCENARIOS, score, friction_demo

NOW = "2026-10-10T04:30:00Z"
R = []
def t(name, c):
    R.append((name, c)); print(("PASS" if c else "FAIL"), name)


def fixture(text="記事の発言サンプル。", statement_type="speech", **kw):
    sp, rc = gen_key(), gen_key()
    sk, rk = key_id(sp.public_key()), key_id(rc.public_key())
    mf = make_consent_manifest(
        [sp, rc], "adv",
        parties=[{"keyid": sk, "role": "speaker", "disclosure": "real_name"},
                 {"keyid": rk, "role": "recorder", "disclosure": "real_name"}],
        terms={"recording": True, "direct_quote": True},
        effective_at="2026-10-01T00:00:00Z")
    st = make_statement(sp, "adv", text, NOW, NOW, NOW, [], "on-record",
                        statement_type=statement_type,
                        valid_from="2026-10-10T00:00:00Z",
                        valid_until="2026-12-31T00:00:00Z", **kw)
    pubs = {sk: sp.public_key(), rk: rc.public_key()}
    return sp, rc, mf, st, pubs


def pkg(objs, pubs, rev=None):
    return {"objects": objs, "pubs": pubs, "revocations": rev or {}}


def main():
    # --- §7 scenario: speaker refuses signature after consenting ---
    sp, rc, mf, st, pubs = fixture()
    bad_st = copy.deepcopy(st)
    bad_st["sigs"] = []  # unsigned statement
    qt = make_quotation(rc, st, [[0, 5]], st["body"]["text"][:5], "pub")
    r = verify_quotation(pkg([mf, bad_st], pubs), qt)
    t("unsigned statement -> UNVERIFIABLE (consent ≠ signed record)",
      r["authenticity"].startswith("FAIL"))

    # --- §7: speaker marks unfavorable content as "required context" ---
    # allowed by design (speaker declares, does not censor); constraint on
    # full text is honest — flag is detection, not prohibition
    st2 = copy.deepcopy(st)
    cc = make_context_constraint(sp, st["body"]["statement_id"],
                                 [[0, len(st["body"]["text"])]],
                                 "full", "required", "speaker")
    qt_clip = make_quotation(rc, st, [[0, 2]], st["body"]["text"][:2], "pub")
    r = verify_quotation(pkg([mf, st, cc], pubs), qt_clip)
    t("overbroad constraint: detected (CONTEXT_FLAG), not silently passed",
      r["label"] == "CONTEXT_FLAG" and r["authenticity"] == "OK")

    # --- §7: extremely short validity — allowed, must not auto-flag ---
    sp2, rc2, mf2, st3, pubs2 = fixture()
    st3["body"]["valid_until"] = "2026-10-10T05:00:00Z"  # 30 min
    st3 = make_statement(sp2, "adv", "速報", NOW, NOW, NOW, [], "on-record",
                         valid_from="2026-10-10T04:00:00Z",
                         valid_until="2026-10-10T05:00:00Z",
                         statement_type="news_comment")
    r = verify_quotation(pkg([mf2, st3], pubs2),
                         make_quotation(rc2, st3, [[0, 2]], "速報", "pub"),
                         t_event="2026-10-10T06:00:00Z")
    t("ultra-short validity: EXPIRED reported, not judged dishonest",
      r["temporal"]["state"] == "EXPIRED" and r["authenticity"] == "OK")

    # --- §7: long commitment masqueraded as short view ---
    st4 = make_statement(sp2, "adv", "4年の公約", NOW, NOW, NOW, [], "on-record",
                         statement_type="campaign_promise",
                         valid_from="2026-10-10T00:00:00Z",
                         valid_until="2026-10-11T00:00:00Z",
                         commitment_start="2026-10-11T00:00:00Z",
                         commitment_end="2030-10-10T00:00:00Z")
    r = verify_quotation(pkg([mf2, st4], pubs2),
                         make_quotation(rc2, st4, [[0, 4]], "4年の公約", "pub"),
                         t_event="2027-01-01T00:00:00Z")
    t("short-view/long-commitment: both axes reported independently",
      r["temporal"]["state"] == "EXPIRED"
      and r["temporal"]["commitment_state"] == "IN_WINDOW")

    # --- §7: third-party leaked recording — signature verifies content,
    #         permission verdict is agreement-level only ---
    mf_off = make_consent_manifest(
        [sp2, rc2], "adv",
        parties=[{"keyid": key_id(sp2.public_key()), "role": "speaker",
                  "disclosure": "anonymous"},
                 {"keyid": key_id(rc2.public_key()), "role": "recorder",
                  "disclosure": "real_name"}],
        terms={"recording": True, "direct_quote": False, "off_record": True},
        effective_at="2026-10-01T00:00:00Z")
    st_off = make_statement(sp2, "adv", "オフレコ内容", NOW, NOW, NOW, [],
                            "off-record", statement_type="off_record")
    p = check_use(pkg([mf_off, st_off], pubs2), st_off, "direct_quote", NOW)
    t("leaked off-record: PROHIBITED_BY_AGREEMENT, not 'illegal'",
      p["verdict"] == "PROHIBITED_BY_AGREEMENT")
    r = verify_quotation(pkg([mf_off, st_off], pubs2),
                         make_quotation(rc2, st_off, [[0, 5]], "オフレコ内容",
                                        "pub"))
    t("leaked off-record: content still authentic (detection vs prevention)",
      r["authenticity"] == "OK")

    # --- eval harness: all golds matched ---
    out = score()
    t("eval: 11/11 context correct",
      all(r["ctx_ok"] for r in out["rows"]))
    t("eval: precision=recall=1.0 on synthetic set",
      out["metrics"]["precision"] == 1.0 and out["metrics"]["recall"] == 1.0)
    fd = friction_demo()
    t("friction demo emits op-count ladder A0->A3",
      len(fd["conditions"]) == 4
      and fd["conditions"][-1]["ops"] > fd["conditions"][0]["ops"])

    n = sum(1 for _, c in R if not c)
    print(f"\n{len(R)} tests, {n} failed")
    sys.exit(1 if n else 0)


if __name__ == "__main__":
    main()
