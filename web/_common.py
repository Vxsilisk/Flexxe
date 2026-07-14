import abc
from typing import Dict, Iterable, List, Mapping, Any
try: from typing import Protocol
except ImportError: Protocol = object # type: ignore
import requests
from requests.structures import CaseInsensitiveDict


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
        """Parse cookies from Set-Cookie headers."""
        _skip = ('path', 'domain', 'expires', 'max-age', 'samesite', 'secure', 'httponly')
        for key in ('set-cookie', 'Set-Cookie'):
            raw = self.headers.get(key, '')
            if not raw:
                continue
            for part in raw.split(','):
                part = part.strip()
                if '=' in part:
                    cookie_part = part.split(';')[0]
                    name, _, value = cookie_part.partition('=')
                    name = name.strip()
                    if name and name.lower() not in _skip:
                        self.cookies[name] = value.strip()

    @classmethod
    def newFURL(cls, url: str, **kwargs:Any) -> 'BaseWebPage':
        """Fetch URL with requests and build WebPage."""
        kwargs.setdefault('timeout', 15)
        response = requests.get(url, **kwargs)
        return cls.newFResponse(response)

    @classmethod
    def newFResponse(cls, response:requests.Response) -> 'BaseWebPage':
        """Build WebPage from a requests.Response."""
        page = cls(response.url, html=response.text, headers=response.headers)
        page.cookies.update({k: v for k, v in response.cookies.items()})
        return page
