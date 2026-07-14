import abc
from http.cookies import SimpleCookie
from typing import Dict, Iterable, List, Mapping, Any
try: from typing import Protocol
except ImportError: Protocol = object # type: ignore
import requests
from requests.structures import CaseInsensitiveDict


#//! Realistic default headers — some WAFs/CDNs vary their response (and thus
#//* the fingerprintable surface) on Accept / Accept-Language / Sec-Fetch.
_DEFAULT_UA = ('Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 '
               '(KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36')

_DEFAULT_HEADERS: Dict[str, str] = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
}


class ITag(Protocol):
    name: str
    attributes: Mapping[str, str]
    inner_html: str


class BaseTag(ITag, abc.ABC):
    def __init__(self, name:str, attributes:Mapping[str, str]) -> None:
        self.name = name
        self.attributes = attributes

    @property
    def inner_html(self) -> str: # type: ignore
        raise NotImplementedError()


class IWebPage(Protocol):
    url: str
    html: str
    headers: Mapping[str, str]
    cookies: Dict[str, str]
    scripts: List[str]
    meta: Mapping[str, str]
    links: List[str]
    def select(self, selector:str) -> Iterable[ITag]:
        raise NotImplementedError()


class BaseWebPage(IWebPage):
    def __init__(self, url:str, html:str, headers:Mapping[str, str]):
        self.url = url
        self.html = html
        self.headers = CaseInsensitiveDict(headers)
        self.cookies: Dict[str, str] = {}
        self.scripts: List[str] = []
        self.links: List[str] = []
        self.meta: Mapping[str, str] = {}
        self._parse_cookies_from_headers()
        self._parse_html()

    def _parse_cookies_from_headers(self) -> None:
        """Parse cookies from any Set-Cookie header.

        Uses ``http.cookies.SimpleCookie`` so attribute values that legitimately
        contain commas (``Expires=Wed, 21 Oct 2025 ...``) cannot corrupt the
        cookie names — a long-standing bug in naive ``split(',')`` parsing.
        Values already populated from a ``requests`` jar (see
        :meth:`newFResponse`) are authoritative and kept.
        """
        for key in ('set-cookie', 'Set-Cookie'):
            raw = self.headers.get(key, '')
            if not raw:
                continue
            try:
                jar: SimpleCookie = SimpleCookie()
                jar.load(raw)
                for name, morsel in jar.items():
                    self.cookies.setdefault(name, morsel.value)
            except Exception:
                pass

    @classmethod
    def newFURL(cls, url: str, *, timeout: float = 15, verify: bool = True,
                headers: Any = None, **kwargs: Any) -> 'BaseWebPage':
        """Fetch ``url`` with realistic browser headers and build a WebPage."""
        merged = dict(_DEFAULT_HEADERS)
        if headers:
            merged.update(headers)
        merged.setdefault('User-Agent', _DEFAULT_UA)
        kwargs.setdefault('allow_redirects', True)
        with requests.Session() as session:
            session.headers.update(merged)
            response = session.get(url, timeout=timeout, verify=verify, **kwargs)
        return cls.newFResponse(response)

    @classmethod
    def newFResponse(cls, response:requests.Response) -> 'BaseWebPage':
        """Build WebPage from a ``requests.Response`` (cookie jar is authoritative)."""
        page = cls(response.url, html=response.text, headers=response.headers)
        page.cookies.update({k: v for k, v in response.cookies.items()})
        return page
