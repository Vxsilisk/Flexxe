<div align="center">

# ✦ Flexxe

### A website technology fingerprinter for Python

**Point it at a URL — get back the stack.**
WAFs, e-commerce platforms, payment processors and the server behind them, in one call.

static fingerprints · security / WAF detection · payment-processor discovery · optional headless deep scan

⋆ ˚ ｡ ⋆ ୨ ⋆ ˚ ｡ ⋆

[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.8-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)
[![Signatures](https://img.shields.io/badge/fingerprints-1%2C498%20techs-f59e0b)](#-how-it-works)
[![Deep scan](https://img.shields.io/badge/deepscan-Playwright-2EAD33?logo=playwright&logoColor=white)](#-deep-scan-optional)
[![Author](https://img.shields.io/badge/by-Vxsilisk-6366f1)](https://github.com/Vxsilisk)

<br>

[**Features**](#-features) · [**Install**](#-installation) · [**Quick start**](#-quick-start) · [**Output**](#-output) · [**Deep scan**](#-deep-scan-optional) · [**How it works**](#-how-it-works)

</div>

---

## ✦ Features

|   | Feature | What it does |
|---|---------|--------------|
| ❍ | **Tech fingerprinting** | Matches HTML, headers, cookies, scripts and meta against **1,498 technologies** across **72 categories** (Wappalyzer-style signature DB). |
| ✸ | **Security / WAF** | Detects Cloudflare, Akamai, Imperva, F5 BIG-IP, AWS WAF/Shield, PerimeterX and more — with variant de-duplication per vendor. |
| ⟡ | **E-commerce** | Identifies Shopify, WooCommerce, Magento, PrestaShop and other storefront platforms. |
| ❖ | **Payment processors** | Flags Stripe, PayPal, Braintree, Adyen, Klarna, MercadoPago and 20+ gateways by network + DOM evidence. |
| ⌗ | **Server & IP** | Resolves the origin server banner and the host's A-record IP. |
| ⬢ | **Deep scan** | Optional Playwright pass: network interception, JS globals, rendered DOM and payment-iframe discovery. |
| ◈ | **Confidence tiers** | Evidence ranked static → `(pw)` Playwright → `(deep)` heuristic; weaker signals dropped when stronger ones exist. |

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

Or run it interactively:

```bash
python -m Flexxe
```

---

## ✦ Output

```json
{
    "status": true,
    "context": "Site Analysis Technologies",
    "url": "https://www.shopify.com/",
    "ip": "23.227.38.33",
    "server": "cloudflare",
    "securities": ["Cloudflare"],
    "ecommerce": ["Shopify"],
    "processors": ["Not Found!"]
}
```

Every list falls back to `["Not Found!"]` when nothing is matched, and `status`
is `false` with an `error` field when the site yields no technologies at all.

---

## ⬢ Deep scan (optional)

With Playwright installed, Flexxe can drive a headless Chromium to catch what a
static fetch misses — technologies loaded by JavaScript, payment iframes and
requests made only at runtime:

```python
result = Flexxe.analyze("https://checkout.example.com")
```

Detections surfaced only by the browser pass are tagged `(pw)`; heuristic
CSP/JS-bundle guesses are tagged `(deep)` and are dropped automatically whenever
stronger evidence exists for the same technology.

---

## ✦ How it works

1. **Fetch** the page with a mobile Chrome user-agent (`requests` + `BeautifulSoup`/`lxml`).
2. **Fingerprint** the response against `data/technologies.json` — regex patterns over
   HTML, headers, cookies, scripts, meta tags and DOM selectors, plus implied-technology resolution.
3. **Classify** matches into securities, e-commerce and payment processors, collapsing
   related vendor variants (e.g. all Cloudflare flavours → `Cloudflare`).
4. **Resolve** the server banner and host IP.
5. *(optional)* **Deep scan** with Playwright for runtime-only signals.

---

<div align="center">

⋆ ˚ ｡ ⋆ ୨ ⋆ ˚ ｡ ⋆

Part of the **Nebula** toolkit · MIT · by [Vxsilisk](https://github.com/Vxsilisk)

</div>
