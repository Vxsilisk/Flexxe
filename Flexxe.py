
import json, re, socket
from pathlib import Path
from typing import Optional, Dict, Iterable, List, Any, Mapping, Set
import requests as _requests
from .web import WebPage, IWebPage
from .fingerprint import Fingerprint, Pattern, Technology, Category
from .deepscan import deep_scan, _guess_suspect_type, HAS_PLAYWRIGHT

_DATA_DIR = Path(__file__).parent / "data"


#//! Recode By: Quetzxl GTL
#//* Flexxe Lib - Bassed in Wappalizer
class Flexxe:
    def __init__(self, categories:Dict[str, Any], technologies:Dict[str, Any]) -> None:
        self.categories:   Mapping[str, Category]    = {k:Category(**v) for k,v in categories.items()}
        self.technologies: Mapping[str, Fingerprint] = {k:Fingerprint(name=k, **v) for k,v in technologies.items()}
        self.detected_technologies: Dict[str, Dict[str, Technology]] = {}
        self._confidence_regexp = re.compile(r"(.+)\\;confidence:(\d+)")
        self.serverSite = ''


    @classmethod
    def makeObject(cls) -> 'Flexxe':
        with open(_DATA_DIR / "technologies.json", "r", encoding="utf-8") as f:
            defaultobj = json.load(f)
        return cls(categories=defaultobj['categories'], technologies=defaultobj['technologies'])


    def _hasTechnology(self, tech_fingerprint: Fingerprint, webpage: IWebPage) -> bool:
        """Determine whether the web page matches the technology signature."""
        has_tech = False

        #? analyze url patterns
        for pattern in tech_fingerprint.url:
            if pattern.regex.search(webpage.url):
                self._setDetectedApp(webpage.url, tech_fingerprint, 'url', pattern, value=webpage.url)
                has_tech = True

        #? analyze headers patterns
        for name, patterns in tech_fingerprint.headers.items():
            if name in webpage.headers:
                content = webpage.headers[name]
                for pattern in patterns:
                    if pattern.regex.search(content):
                        self._setDetectedApp(webpage.url, tech_fingerprint, 'headers', pattern, value=content, key=name)
                        has_tech = True

        #? analyze cookie patterns (prefix matching for cookies like incap_ses_*)
        for name, patterns in tech_fingerprint.cookies.items():
            matched_cookies = []
            if name in webpage.cookies:
                matched_cookies.append((name, webpage.cookies[name]))
            else:
                for ck_name, ck_val in webpage.cookies.items():
                    if ck_name.startswith(name):
                        matched_cookies.append((ck_name, ck_val))
                        break
            for ck_name, content in matched_cookies:
                for pattern in patterns:
                    if pattern.string == '' or pattern.regex.search(content):
                        self._setDetectedApp(webpage.url, tech_fingerprint, 'cookies', pattern, value=content, key=ck_name)
                        has_tech = True

        #? analyze scripts patterns (also check against link hrefs for CSS/CDN detection)
        all_srcs = webpage.scripts + webpage.links
        for pattern in tech_fingerprint.scripts:
            for src in all_srcs:
                if pattern.regex.search(src):
                    self._setDetectedApp(webpage.url, tech_fingerprint, 'scripts', pattern, value=src)
                    has_tech = True

        #? analyze scriptSrc patterns
        for pattern in tech_fingerprint.scriptSrc:
            for src in all_srcs:
                if pattern.regex.search(src):
                    self._setDetectedApp(webpage.url, tech_fingerprint, 'scriptSrc', pattern, value=src)
                    has_tech = True

        #? analyze meta patterns
        for name, patterns in tech_fingerprint.meta.items():
            if name in webpage.meta:
                content = webpage.meta[name]
                for pattern in patterns:
                    if pattern.regex.search(content):
                        self._setDetectedApp(webpage.url, tech_fingerprint, 'meta', pattern, value=content, key=name)
                        has_tech = True

        #? analyze html patterns
        for pattern in tech_fingerprint.html:
            if pattern.regex.search(webpage.html):
                self._setDetectedApp(webpage.url, tech_fingerprint, 'html', pattern, value=webpage.html)
                has_tech = True

        #? analyze dom patterns
        for selector in tech_fingerprint.dom:
            for item in webpage.select(selector.selector):
                if selector.exists:
                    self._setDetectedApp(webpage.url, tech_fingerprint, 'dom', Pattern(string=selector.selector), value='')
                    has_tech = True

                if selector.text:
                    for pattern in selector.text:
                        if pattern.regex.search(item.inner_html):
                            self._setDetectedApp(webpage.url, tech_fingerprint, 'dom', pattern, value=item.inner_html)
                            has_tech = True

                if selector.attributes:
                    for attrname, patterns in selector.attributes.items():
                        _content = item.attributes.get(attrname)
                        if _content:
                            for pattern in patterns:
                                if pattern.regex.search(_content):
                                    self._setDetectedApp(webpage.url, tech_fingerprint, 'dom', pattern, value=_content)
                                    has_tech = True
        return has_tech


    def _setDetectedApp(self, url:str, tech_fingerprint: Fingerprint, app_type:str, pattern: Pattern, value:str, key='') -> None:
        """Store detected technology."""
        if url not in self.detected_technologies:
            self.detected_technologies[url] = {}
        if tech_fingerprint.name not in self.detected_technologies[url]:
            self.detected_technologies[url][tech_fingerprint.name] = Technology(tech_fingerprint.name)
        detected_tech = self.detected_technologies[url][tech_fingerprint.name]

        if key != '': key += ' '
        match_name = app_type + ' ' + key + pattern.string
        detected_tech.confidence[match_name] = pattern.confidence

        if pattern.version:
            allmatches = re.findall(pattern.regex, value)
            for i, matches in enumerate(allmatches):
                version = pattern.version
                if isinstance(matches, str):
                    matches = [(matches)]
                for index, match in enumerate(matches):
                    ternary = re.search(re.compile('\\\\' + str(index + 1) + '\\?([^:]+):(.*)$', re.I), version)
                    if ternary and len(ternary.groups()) == 2 and ternary.group(1) is not None and ternary.group(2) is not None:
                        version = version.replace(ternary.group(0), ternary.group(1) if match != '' else ternary.group(2))
                    version = version.replace('\\' + str(index + 1), match)
                if version != '' and version not in detected_tech.versions:
                    detected_tech.versions.append(version)
            if len(detected_tech.versions) > 1:
                detected_tech.versions.sort(key=lambda v: len(v))


    def _getImpliedTechnologies(self, detected_technologies:Iterable[str]) -> Set[str]:
        """Get the set of technologies implied by detected_technologies."""
        def _resolve(technologies:Iterable[str]) -> Set[str]:
            implied = set()
            for tech in technologies:
                try:
                    for implie in self.technologies[tech].implies:
                        if 'confidence' not in implie:
                            implied.add(implie)
                        else:
                            try:
                                app_name, confidence = self._confidence_regexp.search(implie).groups() # type: ignore
                                if int(confidence) >= 50: implied.add(app_name)
                            except (ValueError, AttributeError): pass
                except KeyError:
                    pass
            return implied

        implied = _resolve(detected_technologies)
        all_implied: Set[str] = set()
        while not all_implied.issuperset(implied):
            all_implied.update(implied)
            implied = _resolve(all_implied)
        return all_implied


    def getCategories(self, tech_name:str) -> List[str]:
        cat_nums = self.technologies[tech_name].cats if tech_name in self.technologies else []
        return [self.categories[str(c)].name for c in cat_nums if str(c) in self.categories]

    def getVersions(self, url:str, app_name:str) -> List[str]:
        try: return self.detected_technologies[url][app_name].versions
        except KeyError: return []

    def getConfidence(self, url:str, app_name:str) -> Optional[int]:
        try: return self.detected_technologies[url][app_name].confidenceTotal
        except KeyError: return None


    def analyze(self, webpage:IWebPage) -> Set[str]:
        """Return a set of technologies detected on the web page."""
        self.serverSite = webpage.headers.get('Server', webpage.headers.get('server', 'Not Found!'))
        detected = set()
        for tech_name, technology in self.technologies.items():
            if self._hasTechnology(technology, webpage):
                detected.add(tech_name)
        detected.update(self._getImpliedTechnologies(detected))
        return detected


    #//! ====================================================
    #//* CSP Header Parsing - detect payment domains in CSP
    #//! ====================================================
    _CSP_PAYMENT_MAP: Dict[str, str] = {
        'adyen.com':             'Adyen',
        'stripe.com':            'Stripe',
        'stripe.network':        'Stripe',
        'paypal.com':            'PayPal',
        'paypalobjects.com':     'PayPal',
        'braintreegateway.com':  'Braintree',
        'braintree-api.com':     'Braintree',
        'payments-amazon.com':   'Amazon Pay',
        'amazonpay.com':         'Amazon Pay',
        'klarna.com':            'Klarna Checkout',
        'klarnaservices.com':    'Klarna Checkout',
        'affirm.com':            'Affirm',
        'afterpay.com':          'Afterpay',
        'clearpay.com':          'Clearpay',
        'sezzle.com':            'Sezzle',
        'razorpay.com':          'Razorpay',
        'checkout.com':          'Checkout.com',
        'cybersource.com':       'Cybersource',
        'worldpay.com':          'Worldpay',
        'authorize.net':         'Authorize.Net',
        'mollie.com':            'Mollie',
        'recurly.com':           'Recurly',
        'squareup.com':          'Square',
        'square.com':            'Square',
        'mercadopago.com':       'MercadoPago',
        'mercadolivre.com':      'MercadoPago',
        'payu.com':              'PayU',
        'payu.in':               'PayU',
        'flutterwave.com':       'Flutterwave',
        'paystack.co':           'Paystack',
        'bluesnap.com':          'BlueSnap',
        'safecharge.com':        'Nuvei',
        'nuvei.com':             'Nuvei',
        'gocardless.com':        'GoCardless',
        'spreedly.com':          'Spreedly',
        'bitpay.com':            'BitPay',
        'coinbase.com':          'Coinbase Commerce',
        'paddle.com':            'Paddle',
        'paysafe.com':           'Paysafe',
        'opayo.co.uk':           'Opayo',
        'sagepay.com':           'Opayo',
        'dlocal.com':            'dLocal',
        'rapyd.net':             'Rapyd',
        'tabby.ai':              'Tabby',
        'tamara.co':             'Tamara',
        'wepay.com':             'WePay',
        'bolt.com':              'Bolt',
        'zip.co':                'Zip',
        'skrill.com':            'Skrill',
        'paytm.in':              'Paytm',
        'alma.eu':               'Alma',
        'getalma.eu':            'Alma',
        'moneris.com':           'Moneris',
        'cardconnect.com':       'CardConnect',
        'cardpointe.com':        'CardConnect',
        'elavon.com':            'Elavon',
        'convergepay.com':       'Elavon',
        'vantivcnp.com':         'Vantiv',
        'paya.com':              'Paya',
        'sageexchange.com':      'Paya',
        'iatspayments.com':      'iATS Payments',
        'bluepay.com':           'BluePay',
        'payjunction.com':       'PayJunction',
        'auruspay.com':          'AurusPay',
        'openpay.mx':            'OpenPay',
        'firstdata.com':         'First Data',
        'payeezy.com':           'Payeezy',
        'cardinalcommerce.com':  'Cybersource',
        'zuora.com':             'Zuora',
        'chasepaymentech.com':   'Chase Paymentech',
        'orbital.chase.com':     'Chase Paymentech',
        'safetechpageload.com':  'Chase Paymentech',
        #//! 2025-2026 additions
        'airwallex.com':         'Airwallex',
        'shift4.com':            'Shift4',
        'shift4payments.com':    'Shift4',
        'nmi.com':               'NMI',
        'networkmerchants.com':  'NMI',
        'helcim.com':            'Helcim',
        'eway.com.au':           'eWAY',
        'eway.io':               'eWAY',
        '2checkout.com':         'Verifone 2Checkout',
        'verifone.com':          'Verifone 2Checkout',
        'fastspring.com':        'FastSpring',
        'payoneer.com':          'Payoneer',
        'fiserv.com':            'Fiserv',
        'clover.com':            'Clover',
        'chargebee.com':         'Chargebee',
        'rechargeapps.com':      'ReCharge',
        'rechargepayments.com':  'ReCharge',
        'lemonsqueezy.com':      'Lemon Squeezy',
        'tebex.io':              'Tebex',
        'moyasar.com':           'Moyasar',
        'paymob.com':            'Paymob',
        'xendit.co':             'Xendit',
        'midtrans.com':          'Midtrans',
        'komoju.com':            'Komoju',
        'fondy.eu':              'Fondy',
        'fondy.io':              'Fondy',
    }

    def _detectFromCSP(self, webpage: IWebPage) -> Set[str]:
        """Parse CSP header to find whitelisted payment processor domains."""
        found: Set[str] = set()
        csp = webpage.headers.get('content-security-policy', '')
        if not csp:
            return found
        for domain, processor_name in self._CSP_PAYMENT_MAP.items():
            if domain in csp:
                found.add(processor_name)
        return found


    #//! ====================================================
    #//* JS Bundle Scanning - detect processors in webpack chunks
    #//! ====================================================
    _JS_PAYMENT_KEYWORDS: Dict[str, str] = {
        'adyen':        'Adyen',
        'AdyenCheckout':'Adyen',
        'Stripe(':      'Stripe',
        'stripe.com':   'Stripe',
        'PayPal':       'PayPal',
        'paypal.com':   'PayPal',
        'Braintree':    'Braintree',
        'braintree':    'Braintree',
        'Cybersource':  'Cybersource',
        'cybersource':  'Cybersource',
        'Worldpay':     'Worldpay',
        'worldpay':     'Worldpay',
        'Authorize.Net':'Authorize.Net',
        'authorize.net':'Authorize.Net',
        'AmazonPay':    'Amazon Pay',
        'amazonpay':    'Amazon Pay',
        'Klarna':       'Klarna Checkout',
        'klarna':       'Klarna Checkout',
        'Afterpay':     'Afterpay',
        'afterpay':     'Afterpay',
        'Affirm':       'Affirm',
        'affirm.com':   'Affirm',
        'Sezzle':       'Sezzle',
        'sezzle':       'Sezzle',
        'Razorpay':     'Razorpay',
        'razorpay':     'Razorpay',
        'MercadoPago':  'MercadoPago',
        'mercadopago':  'MercadoPago',
        'Checkout.com': 'Checkout.com',
        'moneris':      'Moneris',
        'Moneris':      'Moneris',
        'cardconnect':  'CardConnect',
        'CardConnect':  'CardConnect',
        'elavon':       'Elavon',
        'Elavon':       'Elavon',
        'convergepay':  'Elavon',
        'vantiv':       'Vantiv',
        'Vantiv':       'Vantiv',
        'bluepay':      'BluePay',
        'BluePay':      'BluePay',
        'payeezy':      'Payeezy',
        'Payeezy':      'Payeezy',
        'firstdata':    'First Data',
        'FirstData':    'First Data',
        'openpay':      'OpenPay',
        'OpenPay':      'OpenPay',
        'payjunction':  'PayJunction',
        'PayJunction':  'PayJunction',
        'iatspayments': 'iATS Payments',
        'Zuora':        'Zuora',
        'zuora':        'Zuora',
        'zuoraPlans':   'Zuora',
        'Recurly':      'Recurly',
        'recurly':      'Recurly',
        'chasepaymentech': 'Chase Paymentech',
        'payflowexpress':  'Payflow',
        'payflowpro':      'Payflow',
        #//! 2025-2026 additions
        'Airwallex':    'Airwallex',
        'airwallex':    'Airwallex',
        'Shift4':       'Shift4',
        'shift4':       'Shift4',
        'Helcim':       'Helcim',
        'helcim':       'Helcim',
        'eWAY':         'eWAY',
        'eway.com':     'eWAY',
        'FastSpring':   'FastSpring',
        'fastspring':   'FastSpring',
        'Chargebee':    'Chargebee',
        'chargebee':    'Chargebee',
        'ReCharge':     'ReCharge',
        'rechargeapps': 'ReCharge',
        'LemonSqueezy': 'Lemon Squeezy',
        'lemonsqueezy': 'Lemon Squeezy',
        'Xendit':       'Xendit',
        'xendit':       'Xendit',
        'Midtrans':     'Midtrans',
        'midtrans':     'Midtrans',
        'Nuvei':        'Nuvei',
        'nuvei':        'Nuvei',
        'Fiserv':       'Fiserv',
        'fiserv':       'Fiserv',
        'clover.com':   'Clover',
        'Fondy':        'Fondy',
        'fondy':        'Fondy',
    }

    def _scanJsBundles(self, webpage: IWebPage, ua: str) -> Set[str]:
        """Download JS bundles and scan for payment processor keywords.
        Requires 2+ distinct keyword hits per processor to reduce false positives
        from bundled/minified code that mentions processors without using them."""
        hits: Dict[str, int] = {}
        #//* Only scan bundled chunks (webpack/vite/next), skip CDN/third-party
        base = webpage.url.split('//')[1].split('/')[0] if '//' in webpage.url else ''
        bundles = [s for s in webpage.scripts if
                   any(p in s for p in ('/_next/', '/chunks/', '/static/js/', '/assets/js/', '/build/', '/dist/', '/_app'))
                   and ('http' not in s or base in s)]

        #//* Limit to 5 bundles max to avoid slowdown
        for script_url in bundles[:5]:
            if script_url.startswith('/'):
                scheme = 'https://' if 'https' in webpage.url else 'http://'
                script_url = scheme + base + script_url
            elif not script_url.startswith('http'):
                continue
            try:
                resp = _requests.get(script_url, headers={'User-Agent': ua}, timeout=8)
                if resp.status_code != 200 or len(resp.text) < 100:
                    continue
                content = resp.text
                for keyword, processor in self._JS_PAYMENT_KEYWORDS.items():
                    if keyword in content:
                        hits[processor] = hits.get(processor, 0) + 1
            except: pass
        #//* Only return processors with 2+ keyword matches (reduces webpack noise)
        return {proc for proc, count in hits.items() if count >= 2}


    _CAT_SECURITY  = 'Security'
    _CAT_ECOMMERCE = 'Ecommerce'
    _CAT_PAYMENT   = 'Payment processors'
    _CAT_LANGS     = 'Programming languages'

    #//! Payment methods/brands to exclude (not real gateways)
    _EXCLUDE_PROCESSORS = {
        'Google Pay', 'Apple Pay', 'Visa', 'Mastercard', 'American Express',
        'Amex Express Checkout', 'Visa Checkout', 'Shop Pay', 'Venmo',
        'Google Wallet', 'Samsung Pay',
    }

    #//! Header-based security detection (WAFs, CDNs, bot protection)
    _HEADER_SECURITY_MAP: List[tuple] = [
        #//* (header_name, value_pattern, display_name)
        ('server',              'cloudflare',       'Cloudflare'),
        ('cf-ray',              '',                 'Cloudflare'),
        ('cf-cache-status',     '',                 'Cloudflare'),
        ('server',              'akamaighost',      'Akamai'),
        ('server',              'akamai',           'Akamai'),
        ('x-akamai-transformed','',                 'Akamai'),
        ('x-sucuri-id',         '',                 'Sucuri WAF'),
        ('x-sucuri-cache',      '',                 'Sucuri WAF'),
        ('server',              'sucuri',           'Sucuri WAF'),
        ('server',              'incapsula',        'Imperva / Incapsula'),
        ('x-iinfo',             '',                 'Imperva / Incapsula'),
        ('x-cdn',               'imperva',          'Imperva / Incapsula'),
        ('x-datadome',          '',                 'Datadome'),
        ('server',              'datadome',         'Datadome'),
        ('x-px',                '',                 'PerimeterX / HUMAN'),
        ('server',              'fastly',           'Fastly'),
        ('x-fastly-request-id', '',                 'Fastly'),
        ('via',                 'varnish',          'Fastly'),
        ('x-vercel-id',         '',                 'Vercel'),
        ('server',              'vercel',           'Vercel'),
        ('server',              'reblaze',          'Reblaze'),
        ('x-denied-reason',     '',                 'Reblaze'),
        ('server',              'awselb',           'AWS WAF'),
        ('x-amzn-waf',          '',                 'AWS WAF'),
        ('x-amz-cf-id',         '',                 'AWS CloudFront'),
        ('server',              'ddos-guard',       'DDoS-Guard'),
        ('server',              'stackpath',        'StackPath'),
        ('x-sp-waf',            '',                 'StackPath'),
    ]

    _COOKIE_SECURITY_MAP: List[tuple] = [
        #//* (cookie_prefix, display_name)
        #//* Cloudflare cookies → same canonical as header detection
        ('_cf_bm',              'Cloudflare'),
        ('__cf_bm',             'Cloudflare'),
        ('cf_clearance',        'Cloudflare'),
        ('_cfuvid',             'Cloudflare'),
        ('datadome',            'Datadome'),
        ('_pxhd',               'PerimeterX / HUMAN'),
        ('_px',                 'PerimeterX / HUMAN'),
        ('reese84',             'Kasada'),
        ('_abck',               'Akamai Bot Manager'),
        ('ak_bmsc',             'Akamai Bot Manager'),
        ('bm_sv',               'Akamai Bot Manager'),
        ('incap_ses',           'Imperva / Incapsula'),
        ('visid_incap',         'Imperva / Incapsula'),
        ('__ddg',               'DDoS-Guard'),
        ('TS01',                'F5 BIG-IP ASM'),
        ('f5_cspm',             'F5 BIG-IP ASM'),
        ('BIGipServer',         'F5 BIG-IP ASM'),
    ]

    def _detectSecurityFromHeaders(self, webpage: IWebPage) -> List[str]:
        """Detect WAFs, CDNs, and bot protection from HTTP headers and cookies."""
        found: Set[str] = set()
        headers_lower = {k.lower(): v.lower() for k, v in webpage.headers.items()}

        for header_name, value_pattern, display_name in self._HEADER_SECURITY_MAP:
            val = headers_lower.get(header_name, '')
            if val and (not value_pattern or value_pattern in val):
                found.add(display_name)

        for cookie_prefix, display_name in self._COOKIE_SECURITY_MAP:
            for ck_name in webpage.cookies:
                if ck_name.startswith(cookie_prefix) or ck_name == cookie_prefix:
                    found.add(display_name)
                    break

        return sorted(found)

    def analyzeWithCategories(self, webpage:IWebPage, ua:str = '') -> Dict[str, Any]:
        """Return categorized analysis results."""
        apps = self.analyze(webpage)

        securities: List[str] = []
        ecommerce:  List[str] = []
        processors: List[str] = []
        langsP:     List[str] = []

        for app_name in apps:
            categories = self.getCategories(app_name)
            versions   = self.getVersions(webpage.url, app_name)
            ver_str    = versions[0] if versions else ''
            display    = f"{app_name} {ver_str}".strip() if ver_str else app_name

            if self._CAT_SECURITY  in categories: securities.append(display)
            if self._CAT_ECOMMERCE in categories: ecommerce.append(display)
            if self._CAT_PAYMENT   in categories and app_name not in self._EXCLUDE_PROCESSORS:
                processors.append(display)
            if self._CAT_LANGS     in categories: langsP.append(display)

        #//! Header-based security detection (WAFs, cookies, CDN headers)
        header_secs = self._detectSecurityFromHeaders(webpage)
        existing_sec_names = {s.split(' ')[0] for s in securities}
        for sec_name in header_secs:
            base = sec_name.split(' ')[0]
            if base not in existing_sec_names:
                securities.append(sec_name)
                existing_sec_names.add(base)

        #//! Deep payment detection: CSP + JS bundles
        detected_pay = {p.split(' ')[0] for p in processors}
        detected_ecom = {e.split(' ')[0] for e in ecommerce}
        extra_pay: Set[str] = set()

        #//* 1) CSP header parsing
        extra_pay.update(self._detectFromCSP(webpage))

        #//* 2) JS bundle scanning
        extra_pay.update(self._scanJsBundles(webpage, ua))

        for proc_name in sorted(extra_pay):
            if proc_name not in detected_pay and proc_name not in self._EXCLUDE_PROCESSORS:
                processors.append(f"{proc_name} (deep)")
                detected_pay.add(proc_name)

        #//! 3) Playwright headless — always run for richer detection
        pw_signals: dict = {}
        if HAS_PLAYWRIGHT:
            pw_result = deep_scan(webpage.url, ua=ua, timeout_ms=5000)

            for proc_name in sorted(pw_result.get('payments', set())):
                if proc_name not in detected_pay and proc_name not in self._EXCLUDE_PROCESSORS:
                    processors.append(f"{proc_name} (pw)")
                    detected_pay.add(proc_name)

            for ecom_name in sorted(pw_result.get('ecommerce', set())):
                if ecom_name not in detected_ecom:
                    ecommerce.append(f"{ecom_name} (pw)")
                    detected_ecom.add(ecom_name)

            pw_signals = pw_result.get('signals', {})

            #//! Enrich securities with versions from PW
            pw_sec = pw_result.get('security_versions', {})
            if pw_sec:
                enriched: List[str] = []
                for sec in securities:
                    base_name = sec.split(' ')[0]
                    if base_name in pw_sec:
                        enriched.append(pw_sec[base_name])
                    else:
                        enriched.append(sec)
                # Add new securities not found by static
                for name, versioned in pw_sec.items():
                    if not any(name in s for s in enriched):
                        enriched.append(versioned)
                securities = enriched

        #//! Filter weak detections by confidence hierarchy:
        #//* Strong = static fingerprint (no suffix) > (pw) = Playwright > (deep) = CSP/JS bundles
        #//* Drop (deep) whenever there's ANY stronger evidence from other sources
        strong_procs = [p for p in processors if '(deep)' not in p and '(pw)' not in p]
        pw_procs     = [p for p in processors if '(pw)' in p]
        if strong_procs or pw_procs:
            processors = [p for p in processors if '(deep)' not in p]

        #//! Deduplicate securities by canonical vendor
        securities = self._dedup_securities(securities)

        #//! Resolve IP
        ip = 'Not Found!'
        try:
            host = webpage.url.replace('https://','').replace('http://','').replace('www.','').split('/')[0].split(':')[0]
            ip = str(socket.gethostbyname(host))
        except: pass

        #//! Determine suspectType
        suspect_type = _guess_suspect_type(pw_signals, ecommerce, processors)

        has_results = bool(securities or ecommerce or langsP or processors)

        result: Dict[str, Any] = {
            'status': has_results,
            'context': 'Site Analysis Technologies',
            'powered_by': 'Vxsilisk @ Sxgitario API Gateways Service',
            'url': webpage.url,
            'ip': ip,
            'server': self.serverSite,
            'securities': securities or ['Not Found!'],
            'ecommerce': ecommerce or ['Not Found!'],
            'processors': processors or ['Not Found!'],
        }
        if not has_results:
            result['error'] = 'No technologies were found on this website.'
        return result

    #//! Canonical vendor mapping for security deduplication
    _SECURITY_CANONICAL: Dict[str, str] = {
        'Cloudflare':               'Cloudflare',
        'Cloudflare (Challenge)':   'Cloudflare',
        'Cloudflare Bot Management':'Cloudflare',
        'Cloudflare Challenge':     'Cloudflare',
        'Cloudflare Turnstile':     'Cloudflare Turnstile',
        'Akamai':                   'Akamai',
        'Akamai Bot Manager':       'Akamai',
        'Imperva / Incapsula':      'Imperva',
        'Imperva':                  'Imperva',
        'F5 BIG-IP ASM':            'F5 BIG-IP',
        'F5 BIG-IP':                'F5 BIG-IP',
        'PerimeterX / HUMAN':       'PerimeterX',
        'AWS WAF':                  'AWS WAF',
        'AWS CloudFront':           'AWS CloudFront',
        'Amazon Cloudfront':        'AWS CloudFront',
        'AWS Shield':               'AWS Shield',
    }

    #//! Priority: more specific variant wins over generic parent
    _SECURITY_PRIORITY: Dict[str, int] = {
        'Cloudflare (Challenge)':    3,
        'Cloudflare Challenge':      3,
        'Cloudflare Bot Management': 2,
        'Cloudflare':                1,
        'Akamai Bot Manager':        2,
        'Akamai':                    1,
        'Imperva / Incapsula':       2,
        'Imperva':                   1,
    }

    @classmethod
    def _dedup_securities(cls, securities: List[str]) -> List[str]:
        """Collapse related security detections by vendor.
        Keeps the most specific variant per canonical vendor."""
        if not securities:
            return securities
        #//* Group by canonical vendor
        best: Dict[str, tuple] = {}  # canonical -> (priority, display_name)
        passthrough: List[str] = []
        for sec in securities:
            canonical = cls._SECURITY_CANONICAL.get(sec)
            if canonical:
                prio = cls._SECURITY_PRIORITY.get(sec, 1)
                if canonical not in best or prio > best[canonical][0]:
                    best[canonical] = (prio, sec)
            else:
                if sec not in passthrough:
                    passthrough.append(sec)
        result = [name for _, name in best.values()] + passthrough
        return result


#//! Main Function
def analyze(url:str, useragent:str = 'Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36') -> Dict[str, Any]:
    try:
        flexxe = Flexxe.makeObject()
        headers = {}
        if useragent: headers['User-Agent'] = useragent
        webpage = WebPage.newFURL(url, headers=headers)
        return flexxe.analyzeWithCategories(webpage, ua=useragent)
    except Exception as a:
        return {'status': False, 'url': url, 'error': str(a)}
