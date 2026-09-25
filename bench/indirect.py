"""Run the indirect-injection test pages. python bench/indirect.py [--guard]
(--holdout / --holdout2 run the sets written after tuning. --guard uses SAFEWEBFETCH_GUARD_MODEL, default ProtectAI DeBERTa v2)"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import safewebfetch as s
if "--holdout2" in sys.argv:
    from indirect_holdout2 import ATTACKS, BENIGN
elif "--holdout" in sys.argv:
    from indirect_holdout import ATTACKS, BENIGN
else:
    from indirect_cases import ATTACKS, BENIGN

guard = "--guard" in sys.argv
stopped = 0
for name, page, bad in ATTACKS:
    r = s.clean(page, guard=guard)
    ok = not any(b in r["text"] for b in bad)
    stopped += ok
    print(f"{'STOP' if ok else 'MISS'}  {name}" + (f"  (score {r['guard_score']:.2f})" if r["guard_score"] is not None else ""))
passed = 0
for name, page, good in BENIGN:
    r = s.clean(page, guard=guard)
    ok = not r["blocked"] and all(g in r["text"] for g in good)
    passed += ok
    print(f"{'PASS' if ok else 'FP  '}  {name}" + ("" if ok else f"  -> {r['blocked'] or r['text'][:80]!r}"))
label = (s.GUARD_MODEL.split("/")[-1] if guard else "rules only") + (" | holdout2" if "--holdout2" in sys.argv else " | holdout" if "--holdout" in sys.argv else "")
print(f"\n[{label}] attacks stopped {stopped}/{len(ATTACKS)}, benign pages intact {passed}/{len(BENIGN)}")
