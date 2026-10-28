"""Real timing/scaling measurements for SPE paper (measured, not estimated)."""
import time, json, sys
sys.path.insert(0,".")
from bench import _pkg_for, gen_t1_corpus
import bench_v12
from codec import verify_quotation, make_statement, make_quotation, gen_key

corpus = gen_t1_corpus() + bench_v12.gen_t1b()
NOW="2026-01-01T00:00:00+00:00"

# warmup + verify_quotation timing (per quote, all T1 cases, 50 reps)
def bench_verify(reps=50):
    ts=[]
    for _ in range(reps):
        for c in corpus:
            t0=time.perf_counter()
            verify_quotation(c["pkg"], c["qt"], t_event=NOW)
            ts.append((time.perf_counter()-t0)*1000)
    return ts

ts=bench_verify()
ts.sort()
n=len(ts)
res={"verify_ms":{"n":n,"mean":round(sum(ts)/n,4),"median":round(ts[n//2],4),
     "p95":round(ts[int(n*0.95)],4),"min":round(ts[0],4),"max":round(ts[-1],4)}}

# scaling: statement length
pkg,st,sp,rc,sk,rk=_pkg_for("x"*10)
sc={}
for L in [100,1000,10000,100000]:
    pk,st2,sp2,rc2,_,_= _pkg_for("x"*L)
    q=make_quotation(rc2,st2,[[0,L]],"x"*L,"pub")
    t0=time.perf_counter()
    for _ in range(20): verify_quotation(pk,q,t_event=NOW)
    sc[L]=round((time.perf_counter()-t0)/20*1000,3)
res["scaling_by_text_len_ms"]=sc

# registration cost
t0=time.perf_counter()
for _ in range(100):
    make_statement(sp,"s","x"*1000,"t","t","t",[],"on-record")
res["register_stmt_ms"]=round((time.perf_counter()-t0)/100*1000,3)
print(json.dumps(res,indent=1))
