"""Compare the classifier alone (tags stripped, hidden text kept) with the full pipeline.
Run: python bench/vs_classifier.py (needs the [guard] extra)"""
import html, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..")); sys.path.insert(0, HERE)
import safewebfetch as s
import indirect_cases as dev, indirect_holdout as ho, indirect_holdout2 as ho2, indirect_codex as cx, indirect_codex2 as cx2, indirect_codex3 as cx3, indirect_codex4 as cx4

def naive(page):   # the common approach: strip tags (hidden text included) and classify
    return re.sub(r"\s*\n\s*", "\n", html.unescape(re.sub(r"<[^>]+>", "\n", page))).strip()

def protectai_only(page):
    lines = s._lines(naive(page)); bad = s._classifier_lines(lines, s.GUARD_THRESHOLD) or {}
    return "\n".join(l for i, l in enumerate(lines) if i not in bad)

def ours(page):
    return s.clean(page, guard=True)["text"]

for label, mod in [("dev", dev), ("holdout", ho), ("holdout2", ho2), ("codex", cx), ("codex2", cx2), ("codex3", cx3), ("codex4", cx4)]:
    for name, f in [("ProtectAI alone", protectai_only), ("safewebfetch --guard", ours)]:
        st = sum(not any(b in f(p) for b in bad) for _, p, bad in mod.ATTACKS)
        ok = sum(all(g in f(p) for g in good) for _, p, good in mod.BENIGN)
        print(f"{label:8s} {name:22s} attacks stopped {st}/{len(mod.ATTACKS)}  benign intact {ok}/{len(mod.BENIGN)}")
    for n, p, bad in mod.ATTACKS:
        a, b = any(x in protectai_only(p) for x in bad), any(x in ours(p) for x in bad)
        if a != b: print(f"   diff: {n}: ProtectAI alone {'MISS' if a else 'stop'}, ours {'MISS' if b else 'stop'}")
