#!/usr/bin/env python3
"""safewebfetch — a safety gate between the web and your LLM agent.

Blocks SSRF (internal IPs, cloud metadata, DNS rebinding), refuses downloads,
strips hidden text and prompt-injection sentences. Standard library only.
Optional 2nd layer: Meta Llama Prompt Guard 2 (pip install "safewebfetch[guard]").

    safewebfetch https://example.com            # cleaned text
    safewebfetch https://example.com --json     # {"url", "text", "removed", ...}
"""
import argparse, html, http.client, ipaddress, json, re, socket, ssl, sys, urllib.parse, zlib

__version__ = "0.1.0"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"
TEXT_TYPES = ("text/html", "text/plain", "application/xhtml+xml")
MAX_BYTES = 600_000
GUARD_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"
GUARD_THRESHOLD = 0.8


class Blocked(Exception):
    """보안 규칙 위반. 메시지에 이유가 있다."""


def check(url):
    """URL을 검사하고 (스킴, 호스트, 포트, 경로, 연결할 IP)를 돌려준다. 위반이면 Blocked."""
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        raise Blocked("malformed URL")
    if p.scheme not in ("http", "https"):
        raise Blocked(f"scheme not allowed: {p.scheme or '(none)'}")
    if p.username or p.password:
        raise Blocked("credentials in URL")
    if not p.hostname:
        raise Blocked("no host")
    port = port or (443 if p.scheme == "https" else 80)
    if port not in (80, 443):
        raise Blocked(f"port not allowed: {port}")
    try:
        host = p.hostname.encode("idna").decode()
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (UnicodeError, OSError):
        raise Blocked("cannot resolve host")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:   # 사설·루프백·링크로컬·CGNAT·예약 대역 전부 여기서 걸린다
            raise Blocked(f"non-public address: {ip}")
        ips.append(str(ip))
    path = (p.path or "/") + ("?" + p.query if p.query else "")
    return p.scheme, host, port, path, ips[0]


# 검사한 IP로 직접 연결한다 → 검사 뒤 DNS가 내부 IP로 바뀌어도(리바인딩) 소용없다. 인증서는 원래 이름으로 검증.
class _HTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _HTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch(url, timeout=8, max_redirects=3):
    """안전하게 GET 해서 (최종 URL, 페이지 문자열). 막히면 Blocked, 네트워크 오류는 OSError."""
    for _ in range(max_redirects + 1):
        scheme, host, port, path, ip = check(url)   # 리다이렉트마다 다시 검사
        conn = (_HTTPS if scheme == "https" else _HTTP)(host, ip, port, timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": UA, "Accept": "text/html,text/plain;q=0.9",
                                               "Accept-Encoding": "gzip, identity", "Connection": "close"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308):
                url = urllib.parse.urljoin(url, r.getheader("Location") or "")
                continue
            if r.status != 200:
                raise OSError(f"HTTP {r.status}")
            ctype = (r.getheader("Content-Type") or "").lower()
            if not ctype.startswith(TEXT_TYPES):
                raise Blocked(f"not a text response, refused: {ctype or '(none)'}")
            data = r.read(MAX_BYTES)
            enc = (r.getheader("Content-Encoding") or "identity").lower()
        finally:
            conn.close()
        if enc == "gzip":
            data = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, MAX_BYTES)   # 압축 폭탄 방지
        elif enc != "identity":
            raise Blocked(f"unsupported encoding: {enc}")
        m = re.search(r"charset=([\w-]+)", ctype)
        try:
            return url, data.decode(m.group(1) if m else "utf-8", errors="replace")
        except LookupError:
            return url, data.decode("utf-8", errors="replace")
    raise Blocked("too many redirects")


INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
# 이 목록에 정규식을 더하면 규칙이 늘어난다(영어·한국어)
PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?)",
    r"disregard\s+.{0,30}(instructions?|rules)", r"(system|developer)\s+(prompt|message)", r"you\s+are\s+now\b",
    r"new\s+instructions?\s*:", r"\bact\s+as\s+(an?\s+)?(admin|root|developer|system)",
    r"(이전|위의|앞의|기존)\s*(의\s*)?(모든\s*)?(지시|명령|프롬프트|규칙).{0,8}(무시|잊)", r"시스템\s*프롬프트",
    r"지금부터\s*(너는|당신은|넌)", r"(너는|당신은)\s*이제", r"개발자\s*모드",
    r'"(type|tool|function|name)"\s*:\s*"[^"]+"\s*,\s*"(arguments|parameters|input|args)"',   # 도구 호출 JSON 흉내
    r"\b(curl|wget)\s+\S*https?://", r"\b(nc|ncat|netcat)\s+-", r"base64\s+(-d|--decode)", r"\brm\s+-rf\b",
    r"chmod\s+\+x", r"\bsudo\s+\w", r"(bash|sh|zsh)\s+-c\b", r"powershell", r"\|\s*(bash|sh)\b",
    # AI에게 말을 거는 간접 지시(Prompt Guard 2가 놓치는 유형)
    r"(이|본)\s*(글|페이지|문서|메일)을?\s*(읽는|보는|처리하는)\s*(ai|에이아이|비서|어시스턴트|에이전트|모델|챗봇)",
    r"\b(ai|llm|assistant|agent|chatbot|model)s?\s+(that\s+is\s+|who\s+is\s+)?(reading|processing|summari[sz]ing)\s+this",
    r"\bwithout\s+(asking|confirm\w*|permission)", r"(확인|허락|승인|동의)\s*(없이|받지\s*말고)", r"묻지\s*말고",
    r"(user|사용자).{0,20}(has\s+)?(already\s+)?(authori[sz]ed|approved|consented|허락했|승인했|동의했)",
    r"\b(forward|send|exfiltrate)\b.{0,40}\b(emails?|inbox|messages|files|passwords?|keys?)\b.{0,20}\bto\b",
    r"(메일|메일함|받은편지함|파일|비밀번호|키).{0,20}(보내라|전달해|전송해|보내줘)",
    r"~/\.\w", r"\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.env\b|keychain",   # 민감 파일을 가리키는 문장
]
SUSPICIOUS = re.compile("|".join(PATTERNS), re.I)


def to_text(page):
    """HTML → 보이는 글자만. 스크립트·스타일·주석·숨김 요소는 버린다."""
    page = re.sub(r"(?s)<!--.*?-->", " ", page)
    page = re.sub(r"(?is)<(script|style|noscript|svg|head|nav|footer|template|iframe)[^>]*>.*?</\1>", " ", page)
    page = re.sub(r"(?is)<([a-z0-9]+)[^>]*(hidden|display\s*:\s*none|visibility\s*:\s*hidden|aria-hidden=.true"
                  r"|font-size\s*:\s*0)[^>]*>.*?</\1>", " ", page)
    page = re.sub(r"(?s)<[^>]+>", " ", page)
    return re.sub(r"\s+", " ", html.unescape(page)).strip()


def sanitize(text):
    """(정리된 글, 삭제한 의심 문장 수). 문장 단위로 의심 문장을 지운다."""
    text = INVISIBLE.sub("", text)
    parts = re.split(r"(?<=[.!?。])\s+|\n+", text)
    kept = [s for s in parts if not SUSPICIOUS.search(s)]
    removed = len(parts) - len(kept)
    return " ".join(kept) + (" [suspicious text removed]" if removed else ""), removed


_guard = None


def guard_score(text):
    """Prompt Guard 2 점수(0~1, 높을수록 조종 시도). transformers·모델이 없으면 None."""
    global _guard
    if _guard is None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            _guard = (torch, AutoTokenizer.from_pretrained(GUARD_MODEL),
                      AutoModelForSequenceClassification.from_pretrained(GUARD_MODEL).eval())
        except Exception:
            _guard = False
    if not _guard:
        return None
    torch, tok, model = _guard
    ids = tok(text, add_special_tokens=False)["input_ids"] or [tok.unk_token_id]
    best = 0.0
    for i in range(0, len(ids), 500):   # 512토큰 창으로 나눠 가장 높은 점수
        x = [tok.cls_token_id] + ids[i:i + 500] + [tok.sep_token_id]
        with torch.no_grad():
            logits = model(input_ids=torch.tensor([x])).logits
        best = max(best, torch.softmax(logits, -1)[0, 1].item())
    return best


def read(url, guard=False, max_chars=8000):
    """URL → dict(url, text, removed, blocked, guard_score). 에이전트에 넘길 때 쓰는 한 번에 부르는 함수."""
    try:
        final, page = fetch(url)
    except Blocked as e:
        return {"url": url, "text": "", "removed": 0, "blocked": str(e), "guard_score": None}
    text, removed = sanitize(to_text(page)[:max_chars * 2])
    text = text[:max_chars]
    score = guard_score(text) if guard else None
    blocked = None
    if score is not None and score >= GUARD_THRESHOLD:
        text, blocked = "", f"Prompt Guard flagged the page as manipulation ({score:.2f})"
    return {"url": final, "text": text, "removed": removed, "blocked": blocked, "guard_score": score}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="safewebfetch", description="Fetch a web page safely for an LLM.")
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--guard", action="store_true", help="also score with Prompt Guard 2 (needs [guard] extra)")
    ap.add_argument("--max-chars", type=int, default=8000)
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    try:
        r = read(a.url, guard=a.guard, max_chars=a.max_chars)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(r, ensure_ascii=False))
    elif r["blocked"]:
        print(f"blocked: {r['blocked']}", file=sys.stderr)
    else:
        print(r["text"])
    return 2 if r["blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
