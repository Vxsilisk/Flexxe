"""Command-line entry point:  python -m Flexxe <url> [options]"""

import argparse
import json
import sys

from .Flexxe import analyze
from .deepscan import HAS_PLAYWRIGHT
from . import __version__


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='Flexxe',
        description='Fingerprint the technologies powering a website.',
    )
    parser.add_argument('url', nargs='?', help='target URL (prompted if omitted)')
    parser.add_argument('--no-deep', action='store_true',
                        help='skip the Playwright headless deep scan')
    parser.add_argument('--timeout', type=float, default=15,
                        help='per-request timeout in seconds (default: 15)')
    parser.add_argument('--ua', metavar='STRING', default=None,
                        help='override the User-Agent')
    parser.add_argument('--insecure', action='store_true',
                        help='do not verify TLS certificates')
    parser.add_argument('--compact', action='store_true',
                        help='single-line JSON instead of indented')
    parser.add_argument('--version', action='version',
                        version=f'Flexxe {__version__}'
                                f' (playwright: {"yes" if HAS_PLAYWRIGHT else "no"})')
    args = parser.parse_args(argv)

    url = args.url or input('URL: ').strip()
    if not url:
        parser.error('no URL provided')

    kwargs = {'deep': not args.no_deep, 'timeout': args.timeout, 'verify': not args.insecure}
    if args.ua:
        kwargs['useragent'] = args.ua

    result = analyze(url, **kwargs)
    print(json.dumps(result, indent=None if args.compact else 4, ensure_ascii=False))
    return 0 if result.get('status') else 1


if __name__ == '__main__':
    sys.exit(main())
