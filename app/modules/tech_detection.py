"""Technology stack detection (Wappalyzer-style)."""
from __future__ import annotations
import re
import urllib3
import requests
from requests.exceptions import RequestException


# Technology fingerprints: header patterns, HTML patterns, meta patterns
TECHNOLOGIES: dict[str, dict] = {
    # CMS
    "WordPress": {
        "headers": [],
        "html": [r"wp-content", r"wp-includes", r"/wp-json/"],
        "meta": [r"WordPress"],
        "cookies": [r"wordpress_", r"wp-settings"],
        "category": "CMS",
    },
    "Drupal": {
        "headers": [r"X-Generator:\s*Drupal"],
        "html": [r"Drupal\.settings", r"/sites/default/files/", r"drupal\.js"],
        "meta": [r"Drupal"],
        "cookies": [r"SESS[a-f0-9]+"],
        "category": "CMS",
    },
    "Joomla": {
        "headers": [],
        "html": [r"/media/jui/", r"Joomla!", r"/components/com_"],
        "meta": [r"Joomla"],
        "cookies": [],
        "category": "CMS",
    },
    "Shopify": {
        "headers": [r"X-ShopId", r"X-ShopifyRequestId"],
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "meta": [],
        "cookies": [r"_shopify_"],
        "category": "E-commerce",
    },
    "WooCommerce": {
        "headers": [],
        "html": [r"woocommerce", r"WooCommerce"],
        "meta": [],
        "cookies": [r"woocommerce_"],
        "category": "E-commerce",
    },
    "Magento": {
        "headers": [r"X-Magento"],
        "html": [r"Mage\.Cookies", r"skin/frontend/", r"mage/cookies\.js"],
        "meta": [],
        "cookies": [r"frontend="],
        "category": "E-commerce",
    },
    "Ghost": {
        "headers": [r"X-Ghost-Cache"],
        "html": [r"ghost\.js", r"content=\"Ghost"],
        "meta": [r"Ghost"],
        "cookies": [],
        "category": "CMS",
    },
    "Squarespace": {
        "headers": [],
        "html": [r"squarespace\.com", r"static\.squarespace\.com"],
        "meta": [r"Squarespace"],
        "cookies": [r"ss-"],
        "category": "Website Builder",
    },
    "Wix": {
        "headers": [],
        "html": [r"wix\.com", r"X_wixCIDX", r"wixcode-"],
        "meta": [],
        "cookies": [r"svSession"],
        "category": "Website Builder",
    },
    "Webflow": {
        "headers": [],
        "html": [r"webflow\.com", r"data-wf-"],
        "meta": [],
        "cookies": [],
        "category": "Website Builder",
    },

    # JavaScript Frameworks
    "React": {
        "headers": [],
        "html": [r"__REACT_", r"data-reactroot", r"data-reactid", r"react\.development\.js", r"react\.production\.min\.js"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Vue.js": {
        "headers": [],
        "html": [r"vue\.min\.js", r"vue\.js", r"__VUE__", r"data-v-[a-f0-9]+"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Angular": {
        "headers": [],
        "html": [r"ng-version=", r"angular\.min\.js", r"angular\.js"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Next.js": {
        "headers": [r"X-Powered-By:\s*Next\.js"],
        "html": [r"__NEXT_DATA__", r"_next/static/"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Nuxt.js": {
        "headers": [r"X-Powered-By:\s*Nuxt\.js"],
        "html": [r"__NUXT__", r"_nuxt/"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "jQuery": {
        "headers": [],
        "html": [r"jquery[.-][\d.]+(?:\.min)?\.js"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Library",
    },

    # Web Servers / Infrastructure
    "Nginx": {
        "headers": [r"Server:\s*nginx"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Web Server",
    },
    "Apache": {
        "headers": [r"Server:\s*Apache"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Web Server",
    },
    "Cloudflare": {
        "headers": [r"CF-Ray", r"Server:\s*cloudflare"],
        "html": [],
        "meta": [],
        "cookies": [r"__cflb", r"cf_clearance"],
        "category": "CDN / Security",
    },
    "AWS CloudFront": {
        "headers": [r"Via:.*cloudfront", r"X-Amz-Cf-Id"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "CDN",
    },
    "Fastly": {
        "headers": [r"X-Served-By:.*cache-", r"Fastly-Debug-Digest"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "CDN",
    },
    "Vercel": {
        "headers": [r"X-Vercel-Id", r"Server:\s*Vercel"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Hosting",
    },
    "Netlify": {
        "headers": [r"X-Nf-Request-Id", r"Server:\s*Netlify"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Hosting",
    },

    # Programming Languages / Frameworks
    "PHP": {
        "headers": [r"X-Powered-By:\s*PHP"],
        # Only match .php in href/src/action attributes, not free text — avoids false positives
        "html": [r'(?:href|src|action)=["\'][^"\']*\.php'],
        "meta": [],
        "cookies": [r"PHPSESSID"],
        "category": "Programming Language",
    },
    "Laravel": {
        "headers": [],
        "html": [],
        "meta": [],
        "cookies": [r"laravel_session"],
        "category": "Web Framework",
    },
    "Django": {
        "headers": [],
        "html": [r"csrfmiddlewaretoken"],
        "meta": [],
        "cookies": [r"csrftoken", r"sessionid"],
        "category": "Web Framework",
    },
    "Ruby on Rails": {
        "headers": [r"X-Powered-By:\s*Phusion Passenger", r"X-Runtime"],
        "html": [r"authenticity_token"],
        "meta": [],
        "cookies": [r"_session_id"],
        "category": "Web Framework",
    },
    "ASP.NET": {
        "headers": [r"X-Powered-By:\s*ASP\.NET", r"X-AspNet-Version"],
        "html": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "meta": [],
        "cookies": [r"ASP\.NET_SessionId", r"\.ASPXAUTH"],
        "category": "Web Framework",
    },

    # Analytics / Tag Managers
    "Google Analytics": {
        "headers": [],
        "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d+-\d+", r"G-[A-Z0-9]+"],
        "meta": [],
        "cookies": [r"_ga", r"_gid"],
        "category": "Analytics",
    },
    "Google Tag Manager": {
        "headers": [],
        "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
        "meta": [],
        "cookies": [],
        "category": "Tag Manager",
    },
    "Hotjar": {
        "headers": [],
        "html": [r"static\.hotjar\.com", r"hjid:"],
        "meta": [],
        "cookies": [r"_hjid"],
        "category": "Analytics",
    },

    # Security
    "reCAPTCHA": {
        "headers": [],
        "html": [r"google\.com/recaptcha", r"grecaptcha"],
        "meta": [],
        "cookies": [],
        "category": "Security",
    },
    "hCaptcha": {
        "headers": [],
        "html": [r"hcaptcha\.com", r"hcaptcha"],
        "meta": [],
        "cookies": [],
        "category": "Security",
    },

    # ── Additional CMS ───────────────────────────────────────
    "TYPO3": {
        "headers": [r"X-Powered-By:\s*TYPO3"],
        "html": [r"typo3conf/", r"typo3/sysext/"],
        "meta": [r"TYPO3"],
        "cookies": [],
        "category": "CMS",
    },
    "Craft CMS": {
        "headers": [r"X-Powered-By:\s*Craft CMS"],
        "html": [r"cpresources/"],
        "meta": [],
        "cookies": [r"CraftSessionId"],
        "category": "CMS",
    },
    "Umbraco": {
        "headers": [],
        "html": [r"umbraco/", r"umbracoNaviHide"],
        "meta": [],
        "cookies": [r"UMB_UCONTEXT", r"UMB-XSRF-TOKEN"],
        "category": "CMS",
    },
    "October CMS": {
        "headers": [],
        "html": [r"october\.js", r"/app/themes/"],
        "meta": [],
        "cookies": [r"october_session"],
        "category": "CMS",
    },
    "Kentico": {
        "headers": [],
        "html": [r"CMSPages/", r"KenticoCloud", r"kentico"],
        "meta": [],
        "cookies": [r"CMSPreferredCulture", r"CMSCsrfCookie"],
        "category": "CMS",
    },
    "HubSpot CMS": {
        "headers": [],
        "html": [r"hs-sites\.com", r"hsforms\.com", r"hubspotusercontent"],
        "meta": [],
        "cookies": [r"__hstc", r"hubspotutk"],
        "category": "CMS",
    },

    # ── Additional E-commerce ────────────────────────────────
    "PrestaShop": {
        "headers": [],
        "html": [r"prestashop", r"/modules/ps_", r"id_product"],
        "meta": [r"PrestaShop"],
        "cookies": [r"PrestaShop-"],
        "category": "E-commerce",
    },
    "OpenCart": {
        "headers": [],
        "html": [r"catalog/view/theme/", r"route=common/home"],
        "meta": [],
        "cookies": [r"OCSESSID"],
        "category": "E-commerce",
    },
    "BigCommerce": {
        "headers": [r"X-BC-Store-Version"],
        "html": [r"cdn\.bigcommerce\.com", r"bigcommerce\.com"],
        "meta": [],
        "cookies": [r"SHOP_SESSION_TOKEN"],
        "category": "E-commerce",
    },
    "Salesforce Commerce Cloud": {
        "headers": [],
        "html": [r"demandware\.net", r"demandware\.static"],
        "meta": [],
        "cookies": [r"dwsid", r"dwanonymous_"],
        "category": "E-commerce",
    },
    "Ecwid": {
        "headers": [],
        "html": [r"app\.ecwid\.com", r"ecwid\.com/script\.js"],
        "meta": [],
        "cookies": [],
        "category": "E-commerce",
    },

    # ── Additional Website Builders ──────────────────────────
    "Framer": {
        "headers": [],
        "html": [r"framer\.com", r"framerusercontent\.com"],
        "meta": [],
        "cookies": [],
        "category": "Website Builder",
    },
    "Cargo": {
        "headers": [],
        "html": [r"cargocollective\.com"],
        "meta": [],
        "cookies": [],
        "category": "Website Builder",
    },

    # ── Additional JS Frameworks ─────────────────────────────
    "Svelte / SvelteKit": {
        "headers": [],
        "html": [r"__SVELTEKIT_", r"_app/immutable/", r"svelte-"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Gatsby": {
        "headers": [],
        "html": [r"___gatsby", r"gatsby-image", r"/static/gatsby-"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Astro": {
        "headers": [r"X-Powered-By:\s*Astro"],
        "html": [r"astro-island", r"astro-slot", r"/_astro/"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Remix": {
        "headers": [],
        "html": [r"__remixContext", r"__remixRouteModules"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Ember.js": {
        "headers": [],
        "html": [r"Ember\.Application", r"ember\.js", r"ember\.min\.js", r"data-ember-action"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Alpine.js": {
        "headers": [],
        "html": [r"alpine\.js", r"alpinejs", r"x-data="],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "HTMX": {
        "headers": [],
        "html": [r"htmx\.org", r"hx-get=", r"hx-post=", r"hx-swap="],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },
    "Stimulus": {
        "headers": [],
        "html": [r"stimulus", r"data-controller="],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Framework",
    },

    # ── Additional JS Libraries ──────────────────────────────
    "Bootstrap": {
        "headers": [],
        "html": [r"bootstrap\.min\.js", r"bootstrap\.bundle\.min\.js", r'link[^>]*bootstrap[^>]*\.css'],
        "meta": [],
        "cookies": [],
        "category": "UI Framework",
    },
    "Tailwind CSS": {
        "headers": [],
        "html": [r"cdn\.tailwindcss\.com", r"tailwindcss", r'link[^>]*tailwind[^>]*\.css'],
        "meta": [],
        "cookies": [],
        "category": "UI Framework",
    },
    "Bulma": {
        "headers": [],
        "html": [r'link[^>]*bulma[^>]*\.css', r"bulma\.min\.css"],
        "meta": [],
        "cookies": [],
        "category": "UI Framework",
    },
    "Lodash": {
        "headers": [],
        "html": [r"lodash\.min\.js", r"lodash\.js", r"cdn.*lodash"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Library",
    },
    "D3.js": {
        "headers": [],
        "html": [r"d3\.min\.js", r"d3\.v\d", r"d3js\.org"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Library",
    },
    "Chart.js": {
        "headers": [],
        "html": [r"chart\.min\.js", r"chart\.js", r"Chart\.js"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Library",
    },
    "Three.js": {
        "headers": [],
        "html": [r"three\.min\.js", r"three\.js", r"threejs\.org"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Library",
    },
    "Moment.js": {
        "headers": [],
        "html": [r"moment\.min\.js", r"moment\.js"],
        "meta": [],
        "cookies": [],
        "category": "JavaScript Library",
    },

    # ── Additional Web Servers ────────────────────────────────
    "Microsoft IIS": {
        "headers": [r"Server:\s*Microsoft-IIS"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Web Server",
    },
    "LiteSpeed": {
        "headers": [r"Server:\s*LiteSpeed", r"X-LiteSpeed-Cache"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Web Server",
    },
    "Caddy": {
        "headers": [r"Server:\s*Caddy"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Web Server",
    },
    "OpenResty": {
        "headers": [r"Server:\s*openresty"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Web Server",
    },
    "Gunicorn": {
        "headers": [r"Server:\s*gunicorn"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Web Server",
    },

    # ── Additional CDN / WAF ──────────────────────────────────
    "Akamai": {
        "headers": [r"X-Check-Cacheable", r"X-Akamai-", r"Server:\s*AkamaiGHost"],
        "html": [],
        "meta": [],
        "cookies": [r"ak_bmsc", r"bm_sz"],
        "category": "CDN",
    },
    "Sucuri WAF": {
        "headers": [r"X-Sucuri-ID", r"X-Sucuri-Cache"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "WAF / Security",
    },
    "Imperva / Incapsula": {
        "headers": [r"X-Iinfo", r"X-CDN:\s*Incapsula"],
        "html": [],
        "meta": [],
        "cookies": [r"incap_ses_", r"visid_incap_"],
        "category": "WAF / Security",
    },
    "AWS WAF": {
        "headers": [r"X-AMZ-CF-POP", r"x-amzn-requestid"],
        "html": [],
        "meta": [],
        "cookies": [r"aws-waf-token"],
        "category": "WAF / Security",
    },

    # ── Additional Hosting ────────────────────────────────────
    "GitHub Pages": {
        "headers": [r"Server:\s*GitHub\.com"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Hosting",
    },
    "Render": {
        "headers": [r"Render-Origin-Server"],
        "html": [r"onrender\.com"],
        "meta": [],
        "cookies": [],
        "category": "Hosting",
    },
    "Heroku": {
        "headers": [r"Via:.*heroku", r"X-Request-Id.*heroku"],
        "html": [],
        "meta": [],
        "cookies": [r"heroku-session-affinity"],
        "category": "Hosting",
    },
    "Fly.io": {
        "headers": [r"Fly-Request-Id"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Hosting",
    },

    # ── Additional Web Frameworks ─────────────────────────────
    "Express.js": {
        "headers": [r"X-Powered-By:\s*Express"],
        "html": [],
        "meta": [],
        "cookies": [r"connect\.sid"],
        "category": "Web Framework",
    },
    "Symfony": {
        "headers": [r"X-Powered-By:\s*PHP"],
        "html": [r"/_profiler/", r"/bundles/"],
        "meta": [],
        "cookies": [r"sf_redirect", r"PHPSESSID"],
        "category": "Web Framework",
    },
    "CakePHP": {
        "headers": [],
        "html": [],
        "meta": [],
        "cookies": [r"CAKEPHP"],
        "category": "Web Framework",
    },
    "CodeIgniter": {
        "headers": [],
        "html": [],
        "meta": [],
        "cookies": [r"ci_session"],
        "category": "Web Framework",
    },
    "Spring Boot": {
        "headers": [r"X-Application-Context"],
        "html": [],
        "meta": [],
        "cookies": [r"JSESSIONID"],
        "category": "Web Framework",
    },
    "FastAPI": {
        "headers": [r"Server:\s*uvicorn"],
        "html": [r"/openapi\.json", r"/redoc", r"FastAPI"],
        "meta": [],
        "cookies": [],
        "category": "Web Framework",
    },

    # ── Analytics & Marketing ─────────────────────────────────
    "Matomo": {
        "headers": [],
        "html": [r"matomo\.js", r"piwik\.js", r"_paq\.push"],
        "meta": [],
        "cookies": [r"_pk_id\.", r"_pk_ses\."],
        "category": "Analytics",
    },
    "Plausible": {
        "headers": [],
        "html": [r"plausible\.io/js/", r"data-domain.*plausible"],
        "meta": [],
        "cookies": [],
        "category": "Analytics",
    },
    "Mixpanel": {
        "headers": [],
        "html": [r"cdn\.mxpnl\.com", r"mixpanel\.com", r"mixpanel\.init"],
        "meta": [],
        "cookies": [r"mp_"],
        "category": "Analytics",
    },
    "Amplitude": {
        "headers": [],
        "html": [r"cdn\.amplitude\.com", r"amplitude\.getInstance"],
        "meta": [],
        "cookies": [],
        "category": "Analytics",
    },
    "Segment": {
        "headers": [],
        "html": [r"cdn\.segment\.com", r"analytics\.load\(", r"segment\.com/analytics\.js"],
        "meta": [],
        "cookies": [r"ajs_user_id", r"ajs_anonymous_id"],
        "category": "Analytics",
    },
    "FullStory": {
        "headers": [],
        "html": [r"fullstory\.com/s/fs\.js", r"window\[_fs_namespace\]", r"FullStory"],
        "meta": [],
        "cookies": [r"fs_uid"],
        "category": "Analytics",
    },
    "Microsoft Clarity": {
        "headers": [],
        "html": [r"clarity\.ms/tag/", r"clarity\.ms/s/clarity\.js"],
        "meta": [],
        "cookies": [r"_clck", r"_clsk"],
        "category": "Analytics",
    },
    "HubSpot": {
        "headers": [],
        "html": [r"js\.hs-scripts\.com", r"js\.hubspot\.com", r"_hsq\.push"],
        "meta": [],
        "cookies": [r"__hstc", r"hubspotutk", r"__hssc"],
        "category": "Marketing",
    },
    "Marketo": {
        "headers": [],
        "html": [r"munchkin\.marketo\.net", r"munchkin\.js", r"Munchkin\.init"],
        "meta": [],
        "cookies": [r"_mkto_trk"],
        "category": "Marketing",
    },
    "Salesforce Pardot": {
        "headers": [],
        "html": [r"pi\.pardot\.com", r"pardot\.com/pd\.js"],
        "meta": [],
        "cookies": [r"visitor_id"],
        "category": "Marketing",
    },

    # ── Chat & Support ────────────────────────────────────────
    "Intercom": {
        "headers": [],
        "html": [r"widget\.intercom\.io", r"intercomSettings", r"intercom\.io/widget"],
        "meta": [],
        "cookies": [r"intercom-session-", r"intercom-id-"],
        "category": "Live Chat",
    },
    "Zendesk": {
        "headers": [],
        "html": [r"static\.zdassets\.com", r"zendesk\.com", r"zopim\.com"],
        "meta": [],
        "cookies": [r"__zlcmid", r"__cfduid"],
        "category": "Live Chat",
    },
    "Drift": {
        "headers": [],
        "html": [r"js\.driftt\.com", r"drift\.com", r"window\.drift"],
        "meta": [],
        "cookies": [r"driftt_aid"],
        "category": "Live Chat",
    },
    "Crisp": {
        "headers": [],
        "html": [r"client\.crisp\.chat", r"CRISP_WEBSITE_ID"],
        "meta": [],
        "cookies": [r"crisp-client"],
        "category": "Live Chat",
    },
    "Tawk.to": {
        "headers": [],
        "html": [r"embed\.tawk\.to", r"Tawk_API"],
        "meta": [],
        "cookies": [r"TawkConnectionTime"],
        "category": "Live Chat",
    },
    "LiveChat": {
        "headers": [],
        "html": [r"cdn\.livechat\.com", r"livechatinc\.com"],
        "meta": [],
        "cookies": [r"__lc\.cid"],
        "category": "Live Chat",
    },
    "Freshchat": {
        "headers": [],
        "html": [r"wchat\.freshchat\.com", r"freshchat\.com"],
        "meta": [],
        "cookies": [],
        "category": "Live Chat",
    },

    # ── Payment ───────────────────────────────────────────────
    "Stripe": {
        "headers": [],
        "html": [r"js\.stripe\.com/v\d", r"stripe\.js", r"Stripe\.setPublishableKey"],
        "meta": [],
        "cookies": [r"__stripe_mid", r"__stripe_sid"],
        "category": "Payment",
    },
    "PayPal": {
        "headers": [],
        "html": [r"paypal\.com/sdk/js", r"paypalobjects\.com"],
        "meta": [],
        "cookies": [],
        "category": "Payment",
    },
    "Klarna": {
        "headers": [],
        "html": [r"klarna\.com/us/payments", r"x\.klarnacdn\.net"],
        "meta": [],
        "cookies": [],
        "category": "Payment",
    },

    # ── Monitoring / Error Tracking ───────────────────────────
    "Sentry": {
        "headers": [],
        "html": [r"browser\.sentry-cdn\.com", r"sentry\.io", r"Sentry\.init"],
        "meta": [],
        "cookies": [],
        "category": "Monitoring",
    },
    "Datadog": {
        "headers": [],
        "html": [r"datadoghq\.com", r"DD_RUM", r"datadog-rum"],
        "meta": [],
        "cookies": [r"dd_cookie_test_"],
        "category": "Monitoring",
    },
    "New Relic": {
        "headers": [],
        "html": [r"js-agent\.newrelic\.com", r"NREUM", r"newrelic\.com"],
        "meta": [],
        "cookies": [],
        "category": "Monitoring",
    },
    "LogRocket": {
        "headers": [],
        "html": [r"cdn\.logrocket\.io", r"LogRocket\.init"],
        "meta": [],
        "cookies": [],
        "category": "Monitoring",
    },
    "Bugsnag": {
        "headers": [],
        "html": [r"d2wy8f7a9ursnm\.cloudfront\.net", r"bugsnag\.com", r"Bugsnag\.start"],
        "meta": [],
        "cookies": [],
        "category": "Monitoring",
    },

    # ── Maps ──────────────────────────────────────────────────
    "Google Maps": {
        "headers": [],
        "html": [r"maps\.googleapis\.com", r"maps\.google\.com/maps/api"],
        "meta": [],
        "cookies": [],
        "category": "Maps",
    },
    "Mapbox": {
        "headers": [],
        "html": [r"api\.mapbox\.com", r"mapbox\.com/mapbox-gl-js"],
        "meta": [],
        "cookies": [],
        "category": "Maps",
    },
    "Leaflet": {
        "headers": [],
        "html": [r"leaflet\.js", r"leaflet\.css", r"leafletjs\.com"],
        "meta": [],
        "cookies": [],
        "category": "Maps",
    },

    # ── Fonts & Icons ─────────────────────────────────────────
    "Google Fonts": {
        "headers": [],
        "html": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"],
        "meta": [],
        "cookies": [],
        "category": "Fonts",
    },
    "Font Awesome": {
        "headers": [],
        "html": [r"font-awesome", r"fontawesome\.com", r"fa-solid", r"fa-brands"],
        "meta": [],
        "cookies": [],
        "category": "Fonts",
    },
    "Adobe Fonts": {
        "headers": [],
        "html": [r"use\.typekit\.net", r"typekit\.com"],
        "meta": [],
        "cookies": [],
        "category": "Fonts",
    },

    # ── CMS / Headless ────────────────────────────────────────
    "Contentful": {
        "headers": [],
        "html": [r"contentful\.com", r"ctfassets\.net"],
        "meta": [],
        "cookies": [],
        "category": "Headless CMS",
    },
    "Sanity": {
        "headers": [],
        "html": [r"sanity\.io", r"cdn\.sanity\.io"],
        "meta": [],
        "cookies": [],
        "category": "Headless CMS",
    },
    "Strapi": {
        "headers": [r"X-Powered-By:\s*Strapi"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Headless CMS",
    },

    # ── Operating Systems ─────────────────────────────────────
    # Detected via the OS token inside the Server header, e.g.:
    #   Server: Apache/2.4.57 (Ubuntu)
    #   Server: Apache/2.4.6 (CentOS)
    #   Server: Microsoft-IIS/10.0  →  Windows Server 2016/2019/2022
    "Ubuntu": {
        "headers": [r"Server:.*\(Ubuntu"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "Debian": {
        "headers": [r"Server:.*\(Debian"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "CentOS": {
        "headers": [r"Server:.*\(CentOS"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "Red Hat": {
        "headers": [r"Server:.*\(Red Hat", r"Server:.*\(RHEL"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "AlmaLinux": {
        "headers": [r"Server:.*\(AlmaLinux"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "Rocky Linux": {
        "headers": [r"Server:.*\(Rocky"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "Fedora": {
        "headers": [r"Server:.*\(Fedora"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "Amazon Linux": {
        "headers": [r"Server:.*\(Amazon"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "FreeBSD": {
        "headers": [r"Server:.*\(FreeBSD"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "OpenBSD": {
        "headers": [r"Server:.*\(OpenBSD"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "Windows Server": {
        # IIS only runs on Windows Server; ASP.NET headers confirm it too.
        # IIS 10.0 → 2016/2019/2022 · IIS 8.5 → 2012 R2 · IIS 8.0 → 2012
        # IIS 7.5 → 2008 R2 · IIS 7.0 → 2008 · IIS 6.0 → 2003
        "headers": [
            r"Server:\s*Microsoft-IIS",
            r"X-Powered-By:\s*ASP\.NET",
            r"X-AspNet-Version",
            r"Server:.*\(Win(32|64)",
        ],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
    "Unix": {
        "headers": [r"Server:.*\(Unix\)"],
        "html": [],
        "meta": [],
        "cookies": [],
        "category": "Operating System",
    },
}


def _match_patterns(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def run(domain: str, verify_ssl: bool = True) -> dict:
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    detected = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=verify_ssl,
                headers={"User-Agent": "Mozilla/5.0 (compatible; DNS-Spy/1.0)"},
            )
            html = resp.text
            headers_str = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            cookies_str = " ".join(resp.cookies.keys())

            for tech_name, fingerprint in TECHNOLOGIES.items():
                matched = False

                if not matched and _match_patterns(fingerprint["headers"], headers_str):
                    matched = True
                if not matched and _match_patterns(fingerprint["html"], html):
                    matched = True
                if not matched and _match_patterns(fingerprint.get("cookies", []), cookies_str):
                    matched = True

                if matched:
                    detected.append({
                        "name": tech_name,
                        "category": fingerprint["category"],
                    })

            # Group by category
            by_category: dict[str, list[str]] = {}
            for tech in detected:
                cat = tech["category"]
                by_category.setdefault(cat, [])
                by_category[cat].append(tech["name"])

            return {
                "detected": detected,
                "by_category": by_category,
                "count": len(detected),
            }

        except RequestException:
            continue
        except Exception as exc:
            return {"error": f"Tech detection failed: {exc}"}

    return {"detected": [], "by_category": {}, "count": 0, "error": "Could not fetch page for analysis"}
