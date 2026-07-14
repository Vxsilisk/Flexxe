from typing import Iterator, List, Mapping
from bs4 import BeautifulSoup, Tag as bs4_Tag # type: ignore
from functools import cached_property
from ._common import BaseWebPage, BaseTag


def _make_soup(html: str) -> BeautifulSoup:
    """Prefer the fast ``lxml`` parser, fall back to the stdlib one if it
    is not installed so the library still works with core deps only."""
    try:
        return BeautifulSoup(html, 'lxml')
    except Exception:
        return BeautifulSoup(html, 'html.parser')


class Tag(BaseTag):
    def __init__(self, name: str, attributes: Mapping[str, str], soup: bs4_Tag) -> None:
        super().__init__(name, attributes)
        self._soup = soup

    @cached_property
    def inner_html(self) -> str:
        return self._soup.decode_contents()


class WebPage(BaseWebPage):
    def _parse_html(self):
        """Parse HTML with BeautifulSoup to extract scripts, meta, and link tags."""
        self._parsed_html = soup = _make_soup(self.html)

        #//* Extract script src
        self.scripts.extend(script['src'] for script in soup.findAll('script', src=True))

        #//* Extract meta name + meta http-equiv (many WAFs use http-equiv)
        self.meta = {}
        for meta in soup.findAll('meta'):
            name = meta.get('name') or meta.get('http-equiv') or meta.get('property')
            content = meta.get('content', '')
            if name and content:
                self.meta[name.lower()] = content

        #//* Extract link[rel=stylesheet] hrefs — useful for detecting CSS frameworks, CDNs
        self.links = [link['href'] for link in soup.findAll('link', href=True)]

    def select(self, selector: str) -> Iterator[Tag]:
        """Execute a CSS select and return results as Tag objects.

        Wappalyzer signatures occasionally carry selectors that soupsieve cannot
        compile (pseudo-classes it doesn't support, malformed CSS). Such a
        selector must skip that one pattern — never abort the whole scan — so
        compilation errors are swallowed and yield nothing.
        """
        try:
            matches: List[bs4_Tag] = self._parsed_html.select(selector)
        except Exception:
            return
        for item in matches:
            yield Tag(item.name, item.attrs, item)
