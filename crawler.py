import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
from dotenv import load_dotenv
import json
import time
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

load_dotenv()

BASE_URL = os.getenv("TARGET_URL", "http://localhost")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "crawl_result.json")
LOGIN_URL      = os.getenv("LOGIN_URL", "")
LOGIN_ID       = os.getenv("LOGIN_ID", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")


# robots.txt/sitemap.xml 자동 발견 실패 시 사용하는 fallback 경로
'''
TODO:
    - 전체 서비스 대상으로 SEED_PATHS를 수정해야 할 듯.
    - 그누 특화는 남겨두되, 어떻게 남길지는 생각해봐야 할 것 같다...
'''
SEED_PATHS = [
    "/",
    "/bbs/login.php",
    "/bbs/register.php",
    "/bbs/faq.php",
    "/bbs/qalist.php",
    "/adm/",
    "/bbs/board.php",
    "/bbs/write.php",
    "/bbs/search.php",
    "/bbs/memo.php",
]

# 크롤링 제외 패턴 (로그아웃·삭제 등 상태 변경 위험 액션)
EXCLUDE_PATTERNS = [
    r"logout", r"signout",
    r"\.(jpg|jpeg|png|gif|svg|ico|css|js|pdf|zip|woff|ttf|eot)(\?|$)",
]

# 크롤러 동작 설정
class CrawlConfig:
    MAX_PAGES = 500           # 전체 방문 페이지 상한
    MIN_PAGES = 100           # 조기 종료 판단 전 최소 방문 페이지 수
    STAGNATION_LIMIT = 50     # 새 입력 구조가 안 나온 상태로 허용할 페이지 수
    DELAY = 0.3               # 요청 간 대기 시간
    TIMEOUT = 10              # 요청 타임아웃


@dataclass
class FormField:
    # Form 필드 정보 객체
    name: str
    field_type: str
    value: str = ""
    options: list = field(default_factory=list) # select 요소 저장용


@dataclass
class Form:
    # HTML form 전체 정보 객체
    action: str
    method: str
    fields: list = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded" # form 데이터 인코딩 방식


@dataclass
class PageResult:
    url: str
    status_code: int
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    query_params: dict = field(default_factory=dict)
    page_title: str = ""
    is_error_page: bool = False


class Crawler:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(base_url)

        self.session = requests.Session() # 세션 사용으로 쿠키 유지 및 연결 재사용
        self.session.headers.update({     # 요청 헤더를 브라우저 처럼 설정
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
        })

        self.visited: set[str] = set()
        self.queue: deque[str] = deque()
        self.results: list[PageResult] = []

        #url 뒤 query string의 parameter 이름과 form의 field 이름/속성 조합을 입력 구조 시그니처로 만들어 중복 제거
        self.seen_input_structures: set[tuple] = set()
        self.no_new_input_pages: int = 0


# 같은 사이트인지 검사
    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return (
            parsed.scheme in ("http", "https")
            and parsed.netloc == self.parsed_base.netloc
        )


# 크롤링 제외 URL 패턴 검사
    def _is_excluded(self, url: str) -> bool:
        return any(re.search(p, url, re.IGNORECASE) for p in EXCLUDE_PATTERNS)


# URl 정규화
    def _normalize(self, url: str) -> str:
        return urlparse(url)._replace(fragment="").geturl()


# URL 정규화 (query string 제외, path는 기본적으로 "/"로)
    def _normalize_path(self, url: str) -> str:
        parsed = urlparse(self._normalize(url))
        return parsed.path or "/"


# URL에서 query parameter 이름만 추출해 입력 구조 비교용 시그니처 생성
    def _query_signature(self, url: str) -> Optional[tuple]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return None
        return (
            "QUERY",
            "GET",
            parsed.path or "/",
            tuple(sorted(params.keys())),
        )

# Form 구조 비교용 시그니처 생성 (vlaue는 제외, field 이름과 form 속성 위주)
    def _form_signature(self, form: Form) -> tuple:
        field_names = tuple(sorted(ff.name for ff in form.fields if ff.name))
        return (
            "FORM",
            form.method.upper(),
            self._normalize_path(form.action),
            field_names,
            form.enctype,
        )


# 현재 페이지에서 발견한 입력 구조 등록 및 새로 발견한 구조 개수 반환
    def _register_input_structures(self, result: PageResult) -> int:
        new_count = 0

        query_sig = self._query_signature(result.url)
        if query_sig and query_sig not in self.seen_input_structures:
            self.seen_input_structures.add(query_sig)
            new_count += 1

        for form in result.forms:
            form_sig = self._form_signature(form)
            if form_sig not in self.seen_input_structures:
                self.seen_input_structures.add(form_sig)
                new_count += 1

        return new_count


# 조기 종료 조건: MIN_PAGES 이상 방문했는데 최근 STAGNATION_LIMIT 페이지 동안 새 입력 구조가 안 나오면 종료
    def _should_stop_early(self, crawled: int) -> bool:
        return crawled >= CrawlConfig.MIN_PAGES and self.no_new_input_pages >= CrawlConfig.STAGNATION_LIMIT


    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[Form]:
        forms = []
        for form_tag in soup.find_all("form"):
            action = urljoin(page_url, form_tag.get("action", page_url)) # 절대 URL로 변환
            method = form_tag.get("method", "GET").upper()
            enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")
            fields = []

            for inp in form_tag.find_all(["input", "textarea", "select", "button"]):
                name = inp.get("name")
                if not name:
                    continue
                
                if inp.name == "select":    # select 안의 option 값들 수집
                    opts = [o.get("value", o.get_text(strip=True))
                            for o in inp.find_all("option")]
                    fields.append(FormField(name=name, 
                                            field_type="select",
                                            value=opts[0] if opts else "", options=opts))
                elif inp.name == "textarea":
                    fields.append(FormField(name=name, 
                                            field_type="textarea",
                                            value=inp.get_text(strip=True)))
                else:
                    fields.append(FormField(name=name,
                                            field_type=inp.get("type", "text"),
                                            value=inp.get("value", "")))

            forms.append(Form(action=action, method=method, fields=fields, enctype=enctype))
        return forms


# 다음에 방문할 URL 추출
    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links = []
        for tag in soup.find_all("a", href=True):  # a 태그 중 href 속성 있는 것만
            href = tag["href"].strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")): 
                continue  # 무의미한 링크 제외

            normalized = self._normalize(urljoin(page_url, href))
            if self._is_in_scope(normalized) and not self._is_excluded(normalized): # 크롤링 가능 링크인지 검사 (같은 사이트 내부 && 제외패턴 안걸림)
                links.append(normalized)
        return links

# sitemap.xml 또는 robots.txt에서 URL 수집
    def _parse_sitemap(self, url: str) -> set[str]:
        urls = set()
        resp = self._fetch(url)
        if not resp or resp.status_code != 200:
            return urls
        text = resp.text.strip()

        if not text.startswith("<?xml") and "<urlset" not in text and "<sitemapindex" not in text: # sitemap 형식인지
            return urls
        soup = BeautifulSoup(text, "lxml-xml")

        for sitemap_tag in soup.find_all("sitemap"): # sitemap 안에 또 sitemap 있으면 재귀적으로 파싱
            loc = sitemap_tag.find("loc")
            if loc:
                urls.update(self._parse_sitemap(loc.get_text(strip=True)))

        for url_tag in soup.find_all("url"): # url 태그에서 loc 요소 추출
            loc = url_tag.find("loc")
            if loc:
                u = self._normalize(loc.get_text(strip=True))
                if self._is_in_scope(u) and not self._is_excluded(u):
                    urls.add(u)
        return urls

# JS 파일에서 경로 추출
    def _extract_paths_from_js(self, js_url: str) -> set[str]:
        urls = set()
        resp = self._fetch(js_url)
        if not resp or resp.status_code != 200: # js 파일이 정상적으로 로딩 안되면 그냥 종료
            return urls

        paths = re.findall(r'["\'](/[^"\'\s<>]*)["\']', resp.text)

        for path in paths:
            if path.startswith(("//", "/#", "/static/", "/assets/")):
                continue

            u = self._normalize(urljoin(self.base_url + "/", path))

            if self._is_in_scope(u) and not self._is_excluded(u):
                urls.add(u)

        return urls


# 크롤링 시작점 모으기
    def _discover_seeds(self) -> list[str]:
        seeds: set[str] = set()

        # 1. robots.txt
        resp = self._fetch(self.base_url + "/robots.txt")
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip().split("*")[0]
                    if path and path != "/":
                        u = self._normalize(self.base_url + path)
                        if self._is_in_scope(u) and not self._is_excluded(u):
                            seeds.add(u)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    found = self._parse_sitemap(sitemap_url)
                    if found:
                        print(f"[SPIDER] robots.txt Sitemap 지시자: {len(found)}개 URL")
                    seeds.update(found)

        # 2. sitemap.xml / sitemap_index.xml
        for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
            found = self._parse_sitemap(self.base_url + sitemap_path)
            if found:
                print(f"[SPIDER] {sitemap_path}: {len(found)}개 URL 발견")
            seeds.update(found)

        # 3. 메인 페이지 JS 파일에서 경로 추출
        main_resp = self._fetch(self.base_url + "/")
        if main_resp and "text/html" in main_resp.headers.get("Content-Type", ""):
            soup = BeautifulSoup(main_resp.text, "lxml")
            js_found = 0
            for script in soup.find_all("script", src=True):
                js_url = urljoin(self.base_url, script["src"])
                if self._is_in_scope(js_url):
                    found = self._extract_paths_from_js(js_url)
                    js_found += len(found)
                    seeds.update(found)
            if js_found:
                print(f"[SPIDER] JS 파일 분석: {js_found}개 경로 발견")

        # 항상 루트는 포함
        seeds.add(self._normalize(self.base_url + "/"))

        # 4. fallback
        if len(seeds) <= 1:
            print("[SPIDER] 자동 발견 실패 — 기본 SEED_PATHS 사용")
            return [self.base_url + p for p in SEED_PATHS]

        print(f"[SPIDER] 자동 발견 완료: {len(seeds)}개 시드")
        return list(seeds)


# URL 요청
    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=CrawlConfig.TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            print(f"  [ERROR] {url} — {e}", file=sys.stderr)
            return None


    def crawl(self, extra_seeds: list[str] = None) -> list[PageResult]:
        seeds = self._discover_seeds()
        if extra_seeds:
            seeds.extend(extra_seeds)
        for s in seeds:
            self.queue.append(s)

        crawled = 0
        while self.queue and crawled < CrawlConfig.MAX_PAGES:
            url = self.queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)

            print(f"[{crawled+1:03d}] {url}")
            resp = self._fetch(url)
            if resp is None:
                crawled += 1
                self.no_new_input_pages += 1
                if self._should_stop_early(crawled):
                    print(f"       \n[STOP] 최근 {CrawlConfig.STAGNATION_LIMIT}페이지 동안 새 입력 구조가 없어 조기 종료")
                    break
                continue

            result = PageResult(url=url, status_code=resp.status_code)

            # 쿼리 파라미터 추출
            parsed = urlparse(url)
            if parsed.query:
                result.query_params = parse_qs(parsed.query, keep_blank_values=True)
            
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type: # HTML 아닌 페이지는 쿼리만 체크
                new_inputs = self._register_input_structures(result)
                self.no_new_input_pages = 0 if new_inputs else self.no_new_input_pages + 1
                self.results.append(result)
                crawled += 1
                if self._should_stop_early(crawled):
                    print(f"       \n[STOP] 최근 {CrawlConfig.STAGNATION_LIMIT}페이지 동안 새 입력 구조가 없어 조기 종료")
                    break
                time.sleep(CrawlConfig.DELAY)
                continue

            # PHP 에러 페이지 감지
            if "Fatal error" in resp.text or "Warning" in resp.text[:200]:
                result.is_error_page = True
                print(f"       [PHP ERROR] {url}")
                new_inputs = self._register_input_structures(result)
                self.no_new_input_pages = 0 if new_inputs else self.no_new_input_pages + 1
                self.results.append(result)
                crawled += 1
                if self._should_stop_early(crawled):
                    print(f"       \n[STOP] 최근 {CrawlConfig.STAGNATION_LIMIT}페이지 동안 새 입력 구조가 없어 조기 종료")
                    break
                time.sleep(CrawlConfig.DELAY)
                continue

            soup = BeautifulSoup(resp.text, "lxml")
            title = soup.find("title")
            result.page_title = title.get_text(strip=True) if title else ""
            result.forms = self._extract_forms(soup, url)
            result.links = self._extract_links(soup, url)

            new_inputs = self._register_input_structures(result)
            if new_inputs:
                self.no_new_input_pages = 0
                print(f"       [INPUT] 새 입력 구조 {new_inputs}개 발견 / 누적 {len(self.seen_input_structures)}개")
            else:
                self.no_new_input_pages += 1

            for link in result.links:
                if link not in self.visited:
                    self.queue.append(link)

            self.results.append(result)
            crawled += 1

            if self._should_stop_early(crawled):
                print(f"       \n[STOP] 최근 {CrawlConfig.STAGNATION_LIMIT}페이지 동안 새 입력 구조가 없어 조기 종료")
                break

            time.sleep(CrawlConfig.DELAY)

        print(f"\n크롤링 완료: {crawled}페이지 방문")
        print(f"고유 입력 구조 수: {len(self.seen_input_structures)}개")
        return self.results


    def save(self, path: str = OUTPUT_FILE):
        data = []
        for r in self.results:
            data.append({
                "url": r.url,
                "status_code": r.status_code,
                "page_title": r.page_title,
                "is_error_page": r.is_error_page,
                "query_params": r.query_params,
                "forms": [
                    {
                        "action": f.action,
                        "method": f.method,
                        "enctype": f.enctype,
                        "fields": [asdict(ff) for ff in f.fields],
                    }
                    for f in r.forms
                ],
                "links_count": len(r.links),
            })
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
        print(f"결과 저장: {path}")

    def summary(self):
        ok_pages = [r for r in self.results if not r.is_error_page]
        err_pages = [r for r in self.results if r.is_error_page]
        all_forms = [(r.url, f) for r in ok_pages for f in r.forms]
        urls_with_params = [r for r in self.results if r.query_params]
        post_forms = [(url, f) for url, f in all_forms if f.method == "POST"]
        get_forms = [(url, f) for url, f in all_forms if f.method == "GET"]

        sep = "=" * 60
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sum_log.txt")

        # 로그 파일에 요약 저장
        with open(log_path, "w", encoding="utf-8") as log:
            def w(text=""):
                log.write(text + "\n")

            w(f"\n{sep}")
            w("DAST 공격 표면 요약")
            w(sep)
            w(f"총 방문 페이지        : {len(self.results)}")
            w(f"  정상 페이지         : {len(ok_pages)}")
            w(f"  PHP 에러 페이지     : {len(err_pages)}")
            w(f"URL 파라미터 페이지   : {len(urls_with_params)}")
            w(f"고유 입력 구조 수     : {len(self.seen_input_structures)}")
            w(f"Form 총 개수          : {len(all_forms)}")
            w(f"  POST form           : {len(post_forms)}")
            w(f"  GET form            : {len(get_forms)}")

            if post_forms:
                w("\n[POST Form 목록]")
                for url, f in post_forms:
                    fields_str = [ff.name for ff in f.fields]
                    w(f"  URL    : {url}")
                    w(f"  action : {f.action}")
                    w(f"  fields : {fields_str}")
                    w()

            if urls_with_params:
                w(f"\n[URL 파라미터 (상위 15개)]")
                for r in urls_with_params[:15]:
                    w(f"  {r.url}")
                    w(f"    params: {list(r.query_params.keys())}")

            if err_pages:
                w(f"\n[PHP 에러 페이지 (상위 10개)]")
                for r in err_pages[:10]:
                    w(f"  {r.url}  (HTTP {r.status_code})")

        print(f"요약 저장: {log_path}")


if __name__ == "__main__":
    if not BASE_URL or BASE_URL == "http://localhost":
        print("[ERROR] TARGET_URL이 .env에 설정되지 않았습니다.", file=sys.stderr)
        sys.exit(1)

    crawler = Crawler(BASE_URL)
    crawler.crawl()
    crawler.save()
    crawler.summary()
    try:
        from pause_on_exit import pause_if_enabled
        pause_if_enabled()
    except Exception:
        pass
