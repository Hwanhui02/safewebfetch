"""Rule-filter benchmark. Run: pip install huggingface_hub pyarrow && python bench/bench.py
1) 공개 프롬프트 인젝션 데이터셋: 공격을 몇 % 잡고, 정상 문장을 몇 % 잘못 지우나
2) 실제 웹 페이지: 정상 페이지에서 문장을 몇 개 잘못 지우나"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pyarrow.parquet as pq
from huggingface_hub import hf_hub_download
import safewebfetch as s

DATASETS = [("deepset/prompt-injections", "data/test-00000-of-00001-701d16158af87368.parquet", "text", "label"),
            ("xTRam1/safe-guard-prompt-injection", "data/test-00000-of-00001.parquet", "text", "label")]
PAGES = ["https://en.wikipedia.org/wiki/Python_(programming_language)", "https://ko.wikipedia.org/wiki/서울특별시",
         "https://en.wikipedia.org/wiki/Prompt_injection", "https://docs.python.org/3/tutorial/datastructures.html",
         "https://www.gnu.org/philosophy/free-sw.en.html", "https://en.wikipedia.org/wiki/Large_language_model",
         "https://ko.wikipedia.org/wiki/삼성전자", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
         "https://www.rfc-editor.org/rfc/rfc9110.html", "https://en.wikipedia.org/wiki/Email"]

for repo, f, tcol, lcol in DATASETS:
    t = pq.read_table(hf_hub_download(repo, f, repo_type="dataset")).to_pydict()
    rows = list(zip(t[tcol], t[lcol]))
    atk = [x for x, l in rows if l == 1]
    ben = [x for x, l in rows if l == 0]
    tp = sum(s.is_suspicious(x) for x in atk)
    fp = sum(s.is_suspicious(x) for x in ben)
    print(f"{repo}: attacks caught {tp}/{len(atk)} ({tp/len(atk):.0%}), benign flagged {fp}/{len(ben)} ({fp/len(ben):.1%})")

tot_s = tot_r = 0
for u in PAGES:
    try:
        _, page = s.fetch(u)
    except Exception as e:
        print("skip", u, e); continue
    text = s.to_text(page)
    sents = [x for x in text.split("\n") if x.strip()]
    _, removed = s.sanitize(text)
    tot_s += len(sents); tot_r += removed
    print(f"  {removed:3d} removed / {len(sents):4d} lines  {u}")
print(f"real pages: {tot_r} false removals in {tot_s} lines")
