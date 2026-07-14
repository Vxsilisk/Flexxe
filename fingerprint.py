import re
from typing import Optional, Union, Mapping, Dict, List, Any


class Pattern:
    def __init__(self, string:str,
                 regex: Optional['re.Pattern']=None,
                 version: Optional[str]=None,
                 confidence: Optional[str] = None) -> None:
        self.string: str = string
        self.regex: 're.Pattern' = regex or re.compile('', 0)
        self.version: Optional[str] = version
        self.confidence: int = int(confidence) if confidence else 100


class DomSelector:
    def __init__(self,
                 selector: str,
                 exists: Optional[bool] = None,
                 text: Optional[List['Pattern']] = None,
                 attributes: Optional[Mapping[str, List['Pattern']]] = None) -> None:
        self.selector: str = selector
        self.exists: bool = bool(exists)
        self.text: Optional[List['Pattern']] = text
        self.attributes: Optional[Mapping[str, List['Pattern']]] = attributes


class Category:
    def __init__(self, name:str,
                 groups: Optional[List[int]] = None,
                 priority: Optional[int] = None) -> None:
        self.name: str = name
        self.groups: List[int] = groups or []
        self.priority: int = priority or 0


class Technology:
    def __init__(self, name:str) -> None:
        self.name = name
        self.confidence: Dict[str, int] = {}
        self.versions: List[str] = []

    @property
    def confidenceTotal(self) -> int:
        return sum(self.confidence.values())


class Fingerprint:
    def __init__(self, name:str, **attrs: Any) -> None:
        self.name: str = name

        #? Metadata
        self.cats: List[int] = attrs.get('cats', [])
        self.website: str = attrs.get('website', '')
        self.description: Optional[str] = attrs.get('description')
        self.icon: Optional[str] = attrs.get('icon')

        #? Implies
        self.implies: List[str] = self._prepareList(attrs['implies']) if 'implies' in attrs else []

        #? Patterns
        self.dom: List[DomSelector] = self._prepareDom(attrs['dom']) if 'dom' in attrs else []
        self.headers: Mapping[str, List[Pattern]] = self._prepareHeaders(attrs['headers']) if 'headers' in attrs else {}
        self.cookies: Mapping[str, List[Pattern]] = self._prepareCookies(attrs['cookies']) if 'cookies' in attrs else {}
        self.meta: Mapping[str, List[Pattern]] = self._prepareMeta(attrs['meta']) if 'meta' in attrs else {}
        self.html: List[Pattern] = self._preparePattern(attrs['html']) if 'html' in attrs else []
        self.url: List[Pattern] = self._preparePattern(attrs['url']) if 'url' in attrs else []
        self.scriptSrc: List[Pattern] = self._preparePattern(attrs['scriptSrc']) if 'scriptSrc' in attrs else []
        self.scripts: List[Pattern] = self._preparePattern(attrs['scripts']) if 'scripts' in attrs else []


    @staticmethod
    def _prepareList(thing: Any) -> List[Any]:
        return thing if isinstance(thing, list) else [thing]

    @classmethod
    def _preparePattern(cls, pattern: Union[str, List[str]]) -> List[Pattern]:
        """Compile regex patterns, extracting ;key:value metadata."""
        if isinstance(pattern, list):
            result = []
            for p in pattern:
                result.extend(cls._preparePattern(p))
            return result

        attrs: Dict[str, Any] = {}
        parts = pattern.split('\\;')
        for index, expression in enumerate(parts):
            if index == 0:
                attrs['string'] = expression
                try:
                    attrs['regex'] = re.compile(expression, re.I)
                except re.error:
                    attrs['regex'] = re.compile(r'(?!x)x')
            else:
                kv = expression.split(':')
                if len(kv) > 1:
                    key = kv.pop(0)
                    attrs[key] = ':'.join(kv)
        return [Pattern(**attrs)]  # type: ignore

    @classmethod
    def _preparePatternDict(cls, thing: Dict[str, Union[str, List[str]]]) -> Mapping[str, List[Pattern]]:
        for k in thing:
            thing[k] = cls._preparePattern(thing[k])  # type: ignore
        return thing  # type: ignore

    @classmethod
    def _prepareCookies(cls, thing: Dict[str, Union[str, List[str]]]) -> Mapping[str, List[Pattern]]:
        return cls._preparePatternDict({k: v for k, v in thing.items()})

    @classmethod
    def _prepareMeta(cls, thing: Union[str, List[str], Dict[str, Union[str, List[str]]]]) -> Mapping[str, List[Pattern]]:
        if not isinstance(thing, dict):
            thing = {'generator': thing}
        return cls._preparePatternDict({k.lower(): v for k, v in thing.items()})

    @classmethod
    def _prepareHeaders(cls, thing: Dict[str, Union[str, List[str]]]) -> Mapping[str, List[Pattern]]:
        return cls._preparePatternDict({k.lower(): v for k, v in thing.items()})

    @classmethod
    def _prepareDom(cls, thing: Union[str, List[str], Dict[str, Dict[str, Union[str, List[str]]]]]) -> List[DomSelector]:
        selectors = []
        if isinstance(thing, str):
            selectors.append(DomSelector(thing, exists=True))
        elif isinstance(thing, list):
            for o in thing:
                selectors.append(DomSelector(o, exists=True))
        elif isinstance(thing, dict):
            for cssselect, clause in thing.items():
                _text = cls._preparePattern(clause['text']) if clause.get('text') else None
                _attrs = None
                if clause.get('attributes'):
                    _attrs = {}
                    for key, pat in clause['attributes'].items():  # type: ignore
                        _attrs[key] = cls._preparePattern(pat)
                selectors.append(DomSelector(
                    cssselect,
                    exists=True if clause.get('exists') is not None else None,
                    text=_text,
                    attributes=_attrs
                ))
        return selectors
