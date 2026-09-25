"""Rule-filter benchmark. Run: pip install huggingface_hub pyarrow && python bench/bench.py
1) public prompt-injection datasets: % of attacks caught, % of benign prompts flagged
2) real web pages: how many lines of benign pages get removed"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    import pyarrow.parquet as pq
    from huggingface_hub import hf_hub_download
except ImportError:
    pq = None
    print("pyarrow/huggingface_hub missing: skipping datasets, running real pages only")
import safewebfetch as s

DATASETS = [("deepset/prompt-injections", "data/test-00000-of-00001-701d16158af87368.parquet", "text", "label"),
            ("xTRam1/safe-guard-prompt-injection", "data/test-00000-of-00001.parquet", "text", "label")]
PAGES = ["https://en.wikipedia.org/wiki/Python_(programming_language)", "https://ko.wikipedia.org/wiki/서울특별시",
         "https://en.wikipedia.org/wiki/Prompt_injection", "https://docs.python.org/3/tutorial/datastructures.html",
         "https://www.gnu.org/philosophy/free-sw.en.html", "https://en.wikipedia.org/wiki/Large_language_model",
         "https://ko.wikipedia.org/wiki/삼성전자", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
         "https://www.rfc-editor.org/rfc/rfc9110.html", "https://en.wikipedia.org/wiki/Email",
         # topics close to the steering / AI-addressing rules
         "https://en.wikipedia.org/wiki/Artificial_Intelligence_Act", "https://en.wikipedia.org/wiki/Product_recall",
         "https://en.wikipedia.org/wiki/Chatbot", "https://ko.wikipedia.org/wiki/인공지능",
         "https://en.wikipedia.org/wiki/Search_engine_optimization", "https://en.wikipedia.org/wiki/Web_crawler",
         "https://en.wikipedia.org/wiki/Consumer_Reports", "https://ko.wikipedia.org/wiki/리콜"]

for repo, f, tcol, lcol in (DATASETS if pq else []):
    t = pq.read_table(hf_hub_download(repo, f, repo_type="dataset")).to_pydict()
    rows = list(zip(t[tcol], t[lcol]))
    atk = [x for x, l in rows if l == 1]
    ben = [x for x, l in rows if l == 0]
    tp = sum(s.is_suspicious(x) for x in atk)
    fp = sum(s.is_suspicious(x) for x in ben)
    print(f"{repo}: attacks caught {tp}/{len(atk)} ({tp/len(atk):.0%}), benign flagged {fp}/{len(ben)} ({fp/len(ben):.1%})")

tot_s = tot_r = tot_b = 0
for u in PAGES:
    try:
        _, page = s.fetch(u)
    except Exception as e:
        print("skip", u, e); continue
    text = s.to_text(page)
    sents = [x for x in text.split("\n") if x.strip()]
    _, removed = s.sanitize(text)
    tot_s += len(sents); tot_r += removed
    blocked = s.clean(page, guard="--guard" in sys.argv)["blocked"]
    tot_b += bool(blocked)
    print(f"  {removed:3d} removed / {len(sents):4d} lines  {u}" + (f"  BLOCKED: {blocked}" if blocked else ""))
print(f"real pages: {tot_r} false removals in {tot_s} lines; {tot_b} pages dropped whole")
