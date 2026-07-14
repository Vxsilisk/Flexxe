<div align="center">

# ✦ Flexxe

### A website technology fingerprinter for Python

**Point it at a URL — get back the whole stack.**
WAFs, e-commerce platforms, payment processors, CMS, frameworks, analytics, CDN,
languages and the server behind them — in one call.

static fingerprints · security / WAF detection · payment-processor discovery · optional headless deep scan

⋆ ˚ ｡ ⋆ ୨ ⋆ ˚ ｡ ⋆

[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.8-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)
[![Signatures](https://img.shields.io/badge/fingerprints-1%2C498%20techs-f59e0b)](#-how-it-works)
[![Deep scan](https://img.shields.io/badge/deepscan-Playwright-2EAD33?logo=playwright&logoColor=white)](#-deep-scan)
[![Author](https://img.shields.io/badge/by-Vxsilisk-6366f1)](https://github.com/Vxsilisk)

<br>

[**Features**](#-features) · [**Install**](#-installation) · [**Quick start**](#-quick-start) · [**Output**](#-output) · [**API**](#-api) · [**CLI**](#-cli) · [**Deep scan**](#-deep-scan) · [**How it works**](#-how-it-works)

</div>

---

## ✦ Features

|   | Feature | What it does |
|---|---------|--------------|
| ❍ | **Tech fingerprinting** | Matches HTML, headers, cookies, scripts and meta against **1,498 technologies** across **72 categories** (Wappalyzer-style signature DB), with implied-technology resolution. |
| ✸ | **Security / WAF** | Cloudflare, Akamai, Imperva, F5 BIG-IP, AWS WAF/Shield, PerimeterX, Datadome, Kasada, captchas and fraud platforms (Forter, Signifyd, Riskified, Sift…) — de-duplicated per vendor. |
| ⟡ | **E-commerce & CMS** | Shopify, WooCommerce, Magento, PrestaShop, BigCommerce, VTEX, Wix, Squarespace, WordPress and more. |
| ❖ | **Payment processors** | Stripe, PayPal, Braintree, Adyen, Klarna, MercadoPago and **60+ gateways** by CSP, JS-bundle, network and DOM evidence. |
| ◈ | **Full stack readout** | Languages, JS/web frameworks, analytics & tag managers, CDN, web servers — plus a detailed per-technology list with versions, categories and confidence. |
| ⌗ | **Server & IP** | Resolves the origin server banner and the host's A-record IP. |
| ⬢ | **Deep scan** | Optional Playwright pass: network interception, JS globals, rendered DOM, payment iframes and versioned security detection. Loop-safe — usable from sync **and** async code. |
| ⬡ | **Fast & robust** | Signature DB is parsed once and cached; a malformed signature can never abort a scan; cookie parsing is spec-correct. |

---

## ⬡ Installation

```bash
git clone https://github.com/Vxsilisk/Flexxe.git
pip install -r Flexxe/requirements.txt
```

Optional — enable the headless **deep scan**:

```bash
pip install playwright && playwright install chromium
```

> **Requirements:** Python ≥ 3.8. Core deps: `requests`, `beautifulsoup4`, `lxml`.

---

## ✦ Quick start

```python
import Flexxe

result = Flexxe.analyze("https://www.shopify.com")
print(result)
```

A bare host works too (`Flexxe.analyze("shopify.com")` — `https://` is assumed).

---

## ✦ Output

```json
{
    "status": true,
    "url": "https://wordpress.org/news/",
    "ip": "198.143.164.252",
    "server": "nginx",
    "suspect_type": "charge",
    "securities": ["Not Found!"],
    "ecommerce": ["Not Found!"],
    "processors": ["Not Found!"],
    "languages": ["PHP"],
    "cms": ["WordPress"],
    "frameworks": ["Not Found!"],
    "analytics": ["Not Found!"],
    "cdn": ["Not Found!"],
    "web_servers": ["Nginx"],
    "technologies": [
        { "name": "WordPress", "version": null, "categories": ["CMS", "Blogs"], "confidence": 100 },
        { "name": "PHP",       "version": null, "categories": ["Programming languages"], "confidence": 100 },
        { "name": "Nginx",     "version": null, "categories": ["Web servers", "Reverse proxies"], "confidence": 100 }
    ],
    "deep_scan": false,
    "elapsed": 0.083
}
```

Each category list falls back to `["Not Found!"]` when empty; `technologies` is
the complete detailed readout for **every** detected technology. On failure,
`status` is `false` and an `error` field explains why.

---

## ✦ API

```python
Flexxe.analyze(
    url,
    useragent=<mobile Chrome UA>,
    *,
    deep=True,       # run the Playwright deep scan when available
    timeout=15,      # per-request timeout (seconds)
    verify=True,     # verify TLS certificates
)
```

Reuse the parsed signature DB across many calls (it is cached automatically):

```python
from Flexxe import Flexxe, WebPage

engine = Flexxe.makeObject()               # parsed once, reused
page   = WebPage.newFURL("https://site.tld")
report = engine.analyzeWithCategories(page, deep=False)
```

**Async** — call the deep scanner from inside a running event loop without it
blowing up (`asyncio.run` can't nest); Flexxe handles that for you:

```python
import asyncio
from Flexxe import deep_scan_async

async def main():
    signals = await deep_scan_async("https://checkout.example.com")

asyncio.run(main())
```

---

## ✦ CLI

```bash
python -m Flexxe <url> [options]
```

| Option | Effect |
|---|---|
| `--no-deep` | Skip the Playwright deep scan (static only, much faster) |
| `--timeout N` | Per-request timeout in seconds (default 15) |
| `--ua STRING` | Override the User-Agent |
| `--insecure` | Do not verify TLS certificates |
| `--compact` | Single-line JSON |
| `--version` | Print version and whether Playwright is available |

```bash
python -m Flexxe shopify.com --no-deep --compact
```

Exit code is `0` when technologies were found, `1` otherwise.

---

## ⬢ Deep scan

With Playwright installed, Flexxe drives a headless Chromium to catch what a
static fetch misses — technologies loaded by JavaScript, payment iframes and
requests made only at runtime:

- **Network interception** — every request URL matched against 60+ payment and
  e-commerce domains.
- **JS globals & rendered DOM** — `window.Stripe`, WooCommerce gateway markup,
  Shopify payment-brand icons, Magento init blocks, and more.
- **Versioned security** — reCAPTCHA Enterprise / v2 / v3, hCaptcha, Turnstile,
  Datadome, Kasada, Arkose, plus fraud platforms.

Detections found only by the browser pass are tagged `(pw)`; heuristic
CSP/JS-bundle guesses are tagged `(deep)` and dropped automatically when stronger
evidence exists. Disable with `deep=False` (API) or `--no-deep` (CLI).

---

## ✦ How it works

1. **Fetch** the page with realistic browser headers (`requests` + `BeautifulSoup`/`lxml`).
2. **Fingerprint** the response against `data/technologies.json` — regex over HTML,
   headers, cookies, scripts, meta tags and DOM selectors, plus implied-technology resolution.
3. **Classify** matches into securities, e-commerce, payment processors, CMS, frameworks,
   analytics, CDN, languages and web servers, collapsing related vendor variants.
4. **Enrich** payments via CSP whitelist parsing and JS-bundle scanning.
5. **Resolve** the server banner and host IP.
6. *(optional)* **Deep scan** with Playwright for runtime-only signals.

---

<div align="center">

⋆ ˚ ｡ ⋆ ୨ ⋆ ˚ ｡ ⋆

Part of the **Nebula** toolkit · MIT · by [Vxsilisk](https://github.com/Vxsilisk)

</div>
