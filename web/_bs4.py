from typing import Iterator, Mapping
from bs4 import BeautifulSoup, Tag as bs4_Tag # type: ignore
from functools import cached_property
from ._common import BaseWebPage, BaseTag

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
        self._parsed_html = soup = BeautifulSoup(self.html, 'lxml')

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
        """Execute a CSS select and returns results as Tag objects."""
        for item in self._parsed_html.select(selector):
            yield Tag(item.name, item.attrs, item)
