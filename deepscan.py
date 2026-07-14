"""
Deep detection using Playwright headless browser.
Network interception, JS globals, rendered DOM, payment iframes.
"""

import asyncio
from typing import Set, Dict, List, Tuple

try:
    from playwright.async_api import async_playwright, TimeoutError as PwTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


#//! Payment domains (network interception)
_PAY_DOMAINS: Dict[str, str] = {
    'adyen.com':             'Adyen',
    'checkoutshopper':       'Adyen',
    'stripe.com':            'Stripe',
    'stripe.network':        'Stripe',
    'paypal.com':            'PayPal',
    'paypalobjects.com':     'PayPal',
    'braintreegateway.com':  'Braintree',
    'braintree-api.com':     'Braintree',
    'payments-amazon.com':   'Amazon Pay',
    'pay.google.com':        'Google Pay',
    'klarna.com':            'Klarna Checkout',
    'affirm.com':            'Affirm',
    'afterpay.com':          'Afterpay',
    'sezzle.com':            'Sezzle',
    'razorpay.com':          'Razorpay',
    'cybersource.com':       'Cybersource',
    'cardinalcommerce.com':  'Cybersource',
    'worldpay.com':          'Worldpay',
    'authorize.net':         'Authorize.Net',
    'recurly.com':           'Recurly',
    'squareup.com':          'Square',
    'mollie.com':            'Mollie',
    'mercadopago.com':       'MercadoPago',
    'moneris.com':           'Moneris',
    'cardconnect.com':       'CardConnect',
    'cardpointe.com':        'CardConnect',
    'elavon.com':            'Elavon',
    'convergepay.com':       'Elavon',
    'vantivcnp.com':         'Vantiv',
    'eprotect':              'Vantiv',
    'payeezy.com':           'Payeezy',
    'globalgatewaye4':       'Payeezy',
    'firstdata.com':         'First Data',
    'bluepay.com':           'BluePay',
    'zuora.com':             'Zuora',
    'openpay.mx':            'OpenPay',
    'iatspayments.com':      'iATS Payments',
    'payjunction.com':       'PayJunction',
    'chasepaymentech.com':   'Chase Paymentech',
    'safetechpageload.com':  'Chase Paymentech',
    'paysafe.com':           'Paysafe',
    'bolt.com/embed':        'Bolt',
    'connect.bolt.com':      'Bolt',
    'checkout.com':          'Checkout.com',
    'dlocal.com':            'dLocal',
    'flutterwave.com':       'Flutterwave',
    'paystack.co':           'Paystack',
    'gocardless.com':        'GoCardless',
    'bitpay.com':            'BitPay',
    'paddle.com':            'Paddle',
    'rapyd.net':             'Rapyd',
    #//! 2025-2026 additions
    'airwallex.com':         'Airwallex',
    'shift4.com':            'Shift4',
    'shift4payments.com':    'Shift4',
    'nuvei.com':             'Nuvei',
    'safecharge.com':        'Nuvei',
    'nmi.com':               'NMI',
    'networkmerchants.com':  'NMI',
    'helcim.com':            'Helcim',
    'eway.com.au':           'eWAY',
    '2checkout.com':         'Verifone 2Checkout',
    'verifone.com':          'Verifone 2Checkout',
    'fastspring.com':        'FastSpring',
    'chargebee.com':         'Chargebee',
    'rechargeapps.com':      'ReCharge',
    'rechargepayments.com':  'ReCharge',
    'lemonsqueezy.com':      'Lemon Squeezy',
    'xendit.co':             'Xendit',
    'midtrans.com':          'Midtrans',
    'fiserv.com':            'Fiserv',
    'clover.com':            'Clover',
    'fondy.eu':              'Fondy',
    'paymob.com':            'Paymob',
    'moyasar.com':           'Moyasar',
    'komoju.com':            'Komoju',
}

#//! Ecommerce domains (network interception) — strict to avoid false positives
_ECOM_DOMAINS: Dict[str, str] = {
    'cdn.shopify.com':       'Shopify',
    'myshopify.com':         'Shopify',
    'bigcommerce.com':       'BigCommerce',
    'vteximg.com':           'VTEX',
    'vtexcommercestable':    'VTEX',
    'demandware.net':        'Salesforce Commerce Cloud',
    'demandware.static':     'Salesforce Commerce Cloud',
    'ecwid.com':             'Ecwid',
    'tiendanube.com':        'TiendaNube',
    #//! 2025-2026 additions
    'static.parastorage.com':'Wix',
    'wixsite.com':           'Wix',
    'sqspcdn.com':           'Squarespace',
    'squarespace.com':       'Squarespace',
    'volusion.com':          'Volusion',
    'opencart.com':          'OpenCart',
    'webflow.com':           'Webflow',
    'assets-global.website-files.com': 'Webflow',
    'commercetools.com':     'commercetools',
    'medusajs.com':          'Medusa',
    'saleor.io':             'Saleor',
    'swell.is':              'Swell',
    'lightspeedapp.com':     'Lightspeed',
    'lightspeedhq.com':      'Lightspeed',
    'weebly.com':            'Weebly',
    'weeblycloud.com':       'Weebly',
    'woocommerce.com':       'WooCommerce',
}

#//! Full JS evaluation — globals, DOM inspection, rendered scripts, signals
_JS_FULL_CHECK = """() => {
    const pay = [];
    const ecom = [];
    const sec = {};
    const signals = { subscription: false, cart: false, donate: false };

    //=== PAYMENT JS GLOBALS ===
    try { if (window.Stripe) pay.push('Stripe'); } catch(e) {}
    try { if (window.braintree) pay.push('Braintree'); } catch(e) {}
    try { if (window.paypal || window.PayPal) pay.push('PayPal'); } catch(e) {}
    try { if (window.AdyenCheckout || window.adyen) pay.push('Adyen'); } catch(e) {}
    try { if (window.recurly) pay.push('Recurly'); } catch(e) {}
    try { if (window.Klarna) pay.push('Klarna Checkout'); } catch(e) {}
    try { if (window.Affirm || window.affirm) pay.push('Affirm'); } catch(e) {}
    try { if (window.afterpay || window.Afterpay) pay.push('Afterpay'); } catch(e) {}
    try { if (window.Razorpay) pay.push('Razorpay'); } catch(e) {}
    try { if (window.Square) pay.push('Square'); } catch(e) {}
    try { if (window.Zuora) pay.push('Zuora'); } catch(e) {}
    try { if (window.Cybersource || window.Flex) pay.push('Cybersource'); } catch(e) {}
    try { if (window.Moneris) pay.push('Moneris'); } catch(e) {}
    try { if (window.Bolt) pay.push('Bolt'); } catch(e) {}
    try { if (window.Airwallex) pay.push('Airwallex'); } catch(e) {}
    try { if (window.Shift4) pay.push('Shift4'); } catch(e) {}
    try { if (window.Chargebee) pay.push('Chargebee'); } catch(e) {}
    try { if (window.Xendit) pay.push('Xendit'); } catch(e) {}
    try { if (window.snap || window.Midtrans) pay.push('Midtrans'); } catch(e) {}
    try { if (window.Helcim) pay.push('Helcim'); } catch(e) {}
    try { if (window.Nuvei) pay.push('Nuvei'); } catch(e) {}
    try { if (window.Paddle) pay.push('Paddle'); } catch(e) {}
    try { if (window.LemonSqueezy) pay.push('Lemon Squeezy'); } catch(e) {}
    try { if (window.FastSpring) pay.push('FastSpring'); } catch(e) {}
    try { if (window.MercadoPago) pay.push('MercadoPago'); } catch(e) {}

    //=== ECOMMERCE JS GLOBALS ===
    try { if (window.Shopify) ecom.push('Shopify'); } catch(e) {}
    try { if (window.BigCommerce) ecom.push('BigCommerce'); } catch(e) {}
    try { if (window.vtex || window.VTEX) ecom.push('VTEX'); } catch(e) {}
    try { if (window.PrestaShop) ecom.push('PrestaShop'); } catch(e) {}
    try {
        if (window.require && window.require.s && window.require.s.contexts
            && window.require.s.contexts._ && window.require.s.contexts._.config
            && window.require.s.contexts._.config.paths
            && window.require.s.contexts._.config.paths.mage) ecom.push('Magento');
    } catch(e) {}
    try { if (window.wc_add_to_cart_params || window.woocommerce_params || window.wc_cart_params) ecom.push('WooCommerce'); } catch(e) {}
    try { if (window.Ecwid) ecom.push('Ecwid'); } catch(e) {}
    try { if (window.Webflow) ecom.push('Webflow'); } catch(e) {}
    try { if (window.Wix) ecom.push('Wix'); } catch(e) {}
    try { if (window.Static && document.querySelector('[data-wix-provider]')) ecom.push('Wix'); } catch(e) {}
    try { if (window.Squarespace || document.querySelector('[data-squarespace-cacheversion]')) ecom.push('Squarespace'); } catch(e) {}
    try { if (window.Volusion) ecom.push('Volusion'); } catch(e) {}

    //=== RENDERED DOM: payment scripts, iframes, forms ===
    try {
        // All script srcs in rendered DOM (catches dynamically injected scripts)
        const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
        const payScriptMap = {
            'braintree': 'Braintree', 'braintreegateway': 'Braintree',
            'js.stripe.com': 'Stripe', 'stripe.js': 'Stripe',
            'adyen': 'Adyen', 'checkoutshopper': 'Adyen',
            'paypal.com': 'PayPal', 'paypalobjects': 'PayPal',
            'cybersource': 'Cybersource', 'cardinal': 'Cybersource', 'songbird': 'Cybersource',
            'moneris.com': 'Moneris', 'gateway.moneris': 'Moneris',
            'recurly': 'Recurly', 'zuora': 'Zuora',
            'payeezy': 'Payeezy', 'globalgatewaye4': 'Payeezy',
            'authorize.net': 'Authorize.Net', 'js.authorize': 'Authorize.Net',
            'worldpay': 'Worldpay', 'elavon': 'Elavon', 'convergepay': 'Elavon',
            'squareup': 'Square', 'square.js': 'Square',
            'klarna': 'Klarna Checkout', 'affirm': 'Affirm', 'afterpay': 'Afterpay',
            'razorpay': 'Razorpay', 'mollie': 'Mollie', 'openpay': 'OpenPay',
            'bluepay': 'BluePay', 'bolt.com': 'Bolt', 'sezzle': 'Sezzle',
            'checkout.com': 'Checkout.com', 'mercadopago': 'MercadoPago',
            'firstdata': 'First Data', 'vantivcnp': 'Vantiv', 'eprotect': 'Vantiv',
            'airwallex': 'Airwallex', 'shift4': 'Shift4', 'nuvei': 'Nuvei',
            'helcim': 'Helcim', 'chargebee': 'Chargebee', 'rechargeapps': 'ReCharge',
            'xendit': 'Xendit', 'midtrans': 'Midtrans', 'fastspring': 'FastSpring',
            'fiserv': 'Fiserv', 'clover.com': 'Clover', 'lemonsqueezy': 'Lemon Squeezy',
            'paddle.js': 'Paddle', 'paddle.com': 'Paddle',
            'eway.com': 'eWAY', '2checkout': 'Verifone 2Checkout',
        };
        for (const src of scripts) {
            for (const [kw, name] of Object.entries(payScriptMap)) {
                if (src.includes(kw) && !pay.includes(name)) pay.push(name);
            }
        }

        // Ecommerce from rendered scripts
        const ecomScriptMap = {
            'cdn.shopify.com': 'Shopify', 'shopify': 'Shopify',
            'woocommerce': 'WooCommerce', 'wc-ajax': 'WooCommerce',
            'bigcommerce': 'BigCommerce', 'prestashop': 'PrestaShop',
            'vtex': 'VTEX', 'ecwid': 'Ecwid',
            'squarespace': 'Squarespace', 'sqsp': 'Squarespace',
            'webflow': 'Webflow', 'volusion': 'Volusion',
            'parastorage.com': 'Wix', 'wixsite': 'Wix',
            'lightspeed': 'Lightspeed', 'opencart': 'OpenCart',
        };
        for (const src of scripts) {
            for (const [kw, name] of Object.entries(ecomScriptMap)) {
                if (src.includes(kw) && !ecom.includes(name)) ecom.push(name);
            }
        }
    } catch(e) {}

    //=== RENDERED DOM: WooCommerce specific (classes, body classes, data attrs) ===
    try {
        const body = document.body;
        if (body) {
            const bc = body.className.toLowerCase();
            if (bc.includes('woocommerce') || bc.includes('wc-')) ecom.push('WooCommerce');
        }
        if (document.querySelector('.woocommerce, .wc-block-grid, #woocommerce-wrapper, .wc-blocks-checkout'))
            if (!ecom.includes('WooCommerce')) ecom.push('WooCommerce');
    } catch(e) {}

    //=== RENDERED DOM: Magento specific ===
    try {
        if (document.querySelector('[data-mage-init], .mage-init, script[type="text/x-magento-init"]'))
            if (!ecom.includes('Magento')) ecom.push('Magento');
        if (document.querySelector('.catalog-product-view, .checkout-cart-index, .cms-index-index'))
            if (!ecom.includes('Magento')) ecom.push('Magento');
    } catch(e) {}

    //=== RENDERED DOM: Shopify payment brand icons (skip card brands, keep real processors) ===
    try {
        const icons = document.querySelectorAll('svg[aria-labelledby]');
        for (const icon of icons) {
            const label = (icon.getAttribute('aria-labelledby') || '').toLowerCase();
            if (!label.startsWith('pi-')) continue;
            const brand = label.replace('pi-', '');
            if (brand.includes('paypal') && !pay.includes('PayPal')) pay.push('PayPal');
            if (brand.includes('klarna') && !pay.includes('Klarna Checkout')) pay.push('Klarna Checkout');
            if (brand.includes('afterpay') && !pay.includes('Afterpay')) pay.push('Afterpay');
            if (brand.includes('affirm') && !pay.includes('Affirm')) pay.push('Affirm');
        }
    } catch(e) {}

    //=== RENDERED DOM: payment iframes ===
    try {
        const iframes = document.querySelectorAll('iframe[src]');
        const iframeMap = {
            'stripe.com': 'Stripe', 'braintreegateway': 'Braintree',
            'paypal.com': 'PayPal', 'adyen.com': 'Adyen',
            'recurly.com': 'Recurly', 'zuora.com': 'Zuora',
            'cybersource': 'Cybersource', 'moneris': 'Moneris',
            'authorize.net': 'Authorize.Net', 'squareup': 'Square',
            'checkout.com': 'Checkout.com', 'bolt.com': 'Bolt',
            'airwallex': 'Airwallex', 'nuvei': 'Nuvei', 'helcim': 'Helcim',
            'chargebee': 'Chargebee', 'shift4': 'Shift4', 'paddle.com': 'Paddle',
        };
        for (const iframe of iframes) {
            const src = (iframe.src || '').toLowerCase();
            for (const [kw, name] of Object.entries(iframeMap)) {
                if (src.includes(kw) && !pay.includes(name)) pay.push(name);
            }
        }
    } catch(e) {}

    //=== RENDERED DOM: WooCommerce gateway detection from rendered scripts ===
    try {
        const html = document.documentElement.innerHTML;
        const wcGateways = {
            'wc-braintree': 'Braintree', 'wc_braintree': 'Braintree',
            'wc-stripe': 'Stripe', 'wc_stripe': 'Stripe', 'stripe-elements': 'Stripe',
            'wc-paypal': 'PayPal', 'ppcp-': 'PayPal',
            'wc-authorize': 'Authorize.Net', 'wc_authorize_net': 'Authorize.Net',
            'wc-square': 'Square', 'wc_square': 'Square',
            'wc-cybersource': 'Cybersource',
            'wc-moneris': 'Moneris', 'wc_moneris': 'Moneris',
            'wc-payeezy': 'Payeezy', 'wc-firstdata': 'First Data',
            'wc-worldpay': 'Worldpay',
            'wc-elavon': 'Elavon', 'wc_elavon': 'Elavon',
            'wc-adyen': 'Adyen', 'adyen-for-woocommerce': 'Adyen',
            'wc-checkout-com': 'Checkout.com',
            'wc-mollie': 'Mollie', 'mollie-payments': 'Mollie',
            'wc-razorpay': 'Razorpay',
            'wc-openpay': 'OpenPay',
            'wc-airwallex': 'Airwallex', 'airwallex-online': 'Airwallex',
            'wc-nuvei': 'Nuvei', 'nuvei-payments': 'Nuvei',
            'wc-shift4': 'Shift4',
            'wc-xendit': 'Xendit',
            'wc-midtrans': 'Midtrans', 'midtrans-for-woocommerce': 'Midtrans',
            'wc-eway': 'eWAY',
            'wc-recharge': 'ReCharge',
        };
        const lowerHtml = html.toLowerCase();
        for (const [kw, name] of Object.entries(wcGateways)) {
            if (lowerHtml.includes(kw) && !pay.includes(name)) pay.push(name);
        }
    } catch(e) {}

    //=== SECURITY DETECTION WITH VERSIONS ===
    try {
        const html = document.documentElement.innerHTML;
        const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
        const allScripts = scripts.join(' ').toLowerCase();
        const lhtml = html.toLowerCase();

        // reCAPTCHA — Enterprise vs v2 vs v3
        const hasRecaptcha = lhtml.includes('recaptcha') || allScripts.includes('recaptcha');
        if (hasRecaptcha) {
            const hasEnterprise = allScripts.includes('recaptcha/enterprise.js')
                               || allScripts.includes('recaptcha/enterprise')
                               || lhtml.includes('recaptcha/enterprise')
                               || lhtml.includes('grecaptcha.enterprise');
            const hasV3 = allScripts.includes('recaptcha/api.js?render=')
                       || lhtml.includes('grecaptcha.execute')
                       || lhtml.includes('recaptcha-v3')
                       || lhtml.includes('recaptcha/api.js?render');
            const hasV2 = lhtml.includes('g-recaptcha')
                       || lhtml.includes('data-sitekey')
                       || lhtml.includes('grecaptcha.render')
                       || lhtml.includes('recaptcha/api.js"');

            if (hasEnterprise) sec['reCAPTCHA'] = 'reCAPTCHA Enterprise';
            else if (hasV3 && hasV2) sec['reCAPTCHA'] = 'reCAPTCHA v2 + v3';
            else if (hasV3) sec['reCAPTCHA'] = 'reCAPTCHA v3';
            else if (hasV2) sec['reCAPTCHA'] = 'reCAPTCHA v2';
            else sec['reCAPTCHA'] = 'reCAPTCHA';
        }

        // hCaptcha
        if (lhtml.includes('hcaptcha') || allScripts.includes('hcaptcha')) {
            sec['hCaptcha'] = 'hCaptcha';
        }

        // Cloudflare Turnstile
        if (lhtml.includes('cf-turnstile') || allScripts.includes('challenges.cloudflare.com/turnstile')) {
            sec['Cloudflare Turnstile'] = 'Cloudflare Turnstile';
        }

        // Cloudflare (general) — detect via challenge page or cf- headers visible in DOM
        if (lhtml.includes('cdn-cgi/challenge-platform') || lhtml.includes('__cf_chl')) {
            sec['Cloudflare'] = 'Cloudflare (Challenge)';
        } else if (allScripts.includes('cloudflareinsights') || allScripts.includes('cdn-cgi/')) {
            sec['Cloudflare'] = 'Cloudflare';
        }

        // Akamai Bot Manager
        if (allScripts.includes('akamaized.net') || lhtml.includes('_abck') || lhtml.includes('ak_bmsc')) {
            sec['Akamai Bot Manager'] = 'Akamai Bot Manager';
        }

        // Datadome
        if (allScripts.includes('datadome') || lhtml.includes('datadome')) {
            sec['Datadome'] = 'Datadome';
        }

        // PerimeterX / HUMAN
        if (allScripts.includes('px-cdn') || allScripts.includes('perimeterx') || lhtml.includes('_pxhd')) {
            sec['PerimeterX'] = 'PerimeterX / HUMAN';
        }

        // Imperva / Incapsula
        if (lhtml.includes('incapsula') || lhtml.includes('_incap_')) {
            sec['Imperva'] = 'Imperva / Incapsula';
        }

        // Kasada
        if (allScripts.includes('kasada') || lhtml.includes('kpsdk')) {
            sec['Kasada'] = 'Kasada';
        }

        // Shape Security (F5)
        if (allScripts.includes('_imp_apg') || lhtml.includes('_imp_apg')) {
            sec['Shape Security'] = 'Shape Security (F5)';
        }

        // GeeTest
        if (allScripts.includes('geetest') || lhtml.includes('geetest') || lhtml.includes('gt_captcha')) {
            sec['GeeTest'] = 'GeeTest';
        }

        // Arkose Labs / FunCaptcha
        if (allScripts.includes('arkoselabs') || allScripts.includes('funcaptcha')
            || lhtml.includes('arkoselabs') || lhtml.includes('funcaptcha')) {
            sec['Arkose Labs'] = 'Arkose Labs (FunCaptcha)';
        }

        // Wordfence
        if (lhtml.includes('wordfence') || allScripts.includes('wordfence')) {
            sec['Wordfence'] = 'Wordfence';
        }

        // Sucuri
        if (lhtml.includes('sucuri') || allScripts.includes('sucuri')) {
            sec['Sucuri'] = 'Sucuri WAF';
        }

        // AWS WAF
        if (lhtml.includes('aws-waf-token') || lhtml.includes('awswaf')) {
            sec['AWS WAF'] = 'AWS WAF';
        }

        // F5 BIG-IP ASM
        try {
            const cookies = document.cookie;
            if (cookies.includes('TS01') || cookies.includes('f5_cspm') || cookies.includes('BIGipServer')) {
                sec['F5 BIG-IP'] = 'F5 BIG-IP ASM';
            }
        } catch(e) {}

        // Friendly Captcha
        if (lhtml.includes('friendly-captcha') || allScripts.includes('friendlycaptcha')) {
            sec['Friendly Captcha'] = 'Friendly Captcha';
        }

        // mTCaptcha
        if (lhtml.includes('mtcaptcha') || allScripts.includes('mtcaptcha')) {
            sec['mTCaptcha'] = 'mTCaptcha';
        }

        // FingerprintJS Pro / Fingerprint.com
        if (allScripts.includes('fpjs') || allScripts.includes('fingerprint.com')
            || allScripts.includes('fingerprintjs')) {
            sec['FingerprintJS'] = 'FingerprintJS Pro';
        }

        //=== FRAUD DETECTION PLATFORMS ===
        // Forter
        if (allScripts.includes('forter.com') || lhtml.includes('forter')) {
            sec['Forter'] = 'Forter';
        }

        // Signifyd
        if (allScripts.includes('signifyd.com') || lhtml.includes('signifyd')) {
            sec['Signifyd'] = 'Signifyd';
        }

        // Riskified
        if (allScripts.includes('riskified.com') || lhtml.includes('riskified')) {
            sec['Riskified'] = 'Riskified';
        }

        // Sift Science
        if (allScripts.includes('sift.com') || allScripts.includes('siftscience')
            || lhtml.includes('_sift') || lhtml.includes('sift.js')) {
            sec['Sift'] = 'Sift';
        }

        // Kount (Equifax)
        if (allScripts.includes('kount.com') || allScripts.includes('kount.net')
            || lhtml.includes('kount')) {
            sec['Kount'] = 'Kount';
        }

        // ThreatMetrix / LexisNexis
        if (allScripts.includes('threatmetrix') || allScripts.includes('lexisnexis')
            || lhtml.includes('tmx_') || lhtml.includes('threatmetrix')) {
            sec['ThreatMetrix'] = 'ThreatMetrix / LexisNexis';
        }

        // Fastly WAF
        if (allScripts.includes('fastly') || lhtml.includes('fastly-insights')) {
            sec['Fastly'] = 'Fastly';
        }

    } catch(e) {}

    //=== SITE TYPE SIGNALS ===
    try {
        const text = document.body ? document.body.innerText.toLowerCase() : '';

        const subWords = ['subscribe', 'subscription', 'membership', 'recurring', 'monthly plan',
                          'annual plan', 'yearly plan', 'free trial', 'cancel anytime', 'per month',
                          '/mo', '/yr', 'billed monthly', 'billed annually', 'upgrade',
                          'downgrade', 'renew', 'billing cycle'];
        for (const w of subWords) {
            if (text.includes(w)) { signals.subscription = true; break; }
        }

        const cartWords = ['add to cart', 'add to bag', 'buy now', 'shop now',
                           'shopping cart', 'your cart', 'cart total', 'proceed to checkout',
                           'place order', 'shipping address', 'free shipping', 'delivery',
                           'in stock', 'out of stock', 'size chart', 'add to wishlist'];
        for (const w of cartWords) {
            if (text.includes(w)) { signals.cart = true; break; }
        }

        const donateWords = ['donate', 'donation', 'give now', 'contribute', 'support us',
                             'tax-deductible', 'nonprofit', 'charity'];
        for (const w of donateWords) {
            if (text.includes(w)) { signals.donate = true; break; }
        }
    } catch(e) {}

    return { pay, ecom, sec, signals };
}"""


def _match_requests(urls: List[str]) -> Tuple[Set[str], Set[str]]:
    """Match captured request URLs against payment + ecommerce maps."""
    payments: Set[str] = set()
    ecommerce: Set[str] = set()
    for req_url in urls:
        rl = req_url.lower()
        for domain, name in _PAY_DOMAINS.items():
            if domain in rl:
                payments.add(name)
        for domain, name in _ECOM_DOMAINS.items():
            if domain in rl:
                ecommerce.add(name)
    return payments, ecommerce


def _guess_suspect_type(signals: dict, ecommerce: List[str], processors: List[str]) -> str:
    """auth = subscriptions/memberships. charge = purchases/donations."""
    sub = signals.get('subscription', False)
    cart = signals.get('cart', False)
    donate = signals.get('donate', False)

    if cart and not sub:
        return 'charge'
    if sub and not cart:
        return 'auth'
    if sub and cart:
        return 'charge'
    if donate:
        return 'charge'
    return 'charge'


async def _deep_scan_async(url: str, ua: str, timeout_ms: int) -> Dict:
    pw_payments: Set[str] = set()
    pw_ecommerce: Set[str] = set()
    signals: dict = {}
    captured: List[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
                  '--disable-extensions', '--disable-background-networking']
        )
        context = await browser.new_context(
            user_agent=ua or 'Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36',
            java_script_enabled=True,
            ignore_https_errors=True,
        )

        page = await context.new_page()
        await page.route("**/*.{png,jpg,jpeg,gif,webp,svg,ico,woff,woff2,ttf,eot}", lambda route: route.abort())
        page.on("request", lambda req: captured.append(req.url))

        #//* 1) Load page, wait for JS
        try:
            await page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)
            await page.wait_for_timeout(1500)
        except: pass

        #//* 2) Full JS evaluation (globals + rendered DOM + signals + security)
        sec_versions: Dict[str, str] = {}
        try:
            result = await page.evaluate(_JS_FULL_CHECK)
            pw_payments.update(result.get('pay', []))
            pw_ecommerce.update(result.get('ecom', []))
            sec_versions = result.get('sec', {})
            signals = result.get('signals', {})
        except: pass

        #//* 3) Check iframe URLs (PW-level, not DOM-level)
        try:
            for frame in page.frames:
                fl = frame.url.lower()
                for domain, name in _PAY_DOMAINS.items():
                    if domain in fl:
                        pw_payments.add(name)
        except: pass

        #//* 4) Match all captured network requests
        net_pay, net_ecom = _match_requests(captured)
        pw_payments.update(net_pay)
        pw_ecommerce.update(net_ecom)

        await browser.close()

    return {
        'payments': pw_payments,
        'ecommerce': pw_ecommerce,
        'security_versions': sec_versions,
        'signals': signals,
    }


def deep_scan(url: str, ua: str = '', timeout_ms: int = 5000) -> Dict:
    """Sync wrapper for async deep scan."""
    _empty = {'payments': set(), 'ecommerce': set(), 'security_versions': {}, 'signals': {}}
    if not HAS_PLAYWRIGHT:
        return _empty
    try:
        return asyncio.run(_deep_scan_async(url, ua, timeout_ms))
    except Exception:
        return _empty
