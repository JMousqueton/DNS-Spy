"""Detect SaaS services from DNS TXT records."""
from __future__ import annotations
import re

# Each entry: (pattern_regex, service_name, category, url)
_RULES: list[tuple[str, str, str, str]] = [
    # --- Email & Collaboration ---
    (r"include:_spf\.google\.com|google-site-verification=",       "Google Workspace",       "Email & Collaboration", "https://workspace.google.com"),
    (r"include:spf\.protection\.outlook\.com|include:spf\.outlook\.com|MS=ms?\d+|v=verifydomain", "Microsoft 365", "Email & Collaboration", "https://www.microsoft.com/microsoft-365"),
    (r"include:spf\.zoho\.com",                                    "Zoho Mail",              "Email & Collaboration", "https://www.zoho.com/mail"),
    (r"include:_spf\.fastmail\.com",                               "Fastmail",               "Email & Collaboration", "https://www.fastmail.com"),
    (r"include:_spf\.protonmail\.ch|protonmail-verification=",     "Proton Mail",            "Email & Collaboration", "https://proton.me/mail"),
    (r"slack-domain-verification=",                                "Slack",                  "Email & Collaboration", "https://slack.com"),
    (r"ZOOM_verify_",                                              "Zoom",                   "Email & Collaboration", "https://zoom.us"),
    (r"include:mail\.zendesk\.com|zendesk-verification=",          "Zendesk",                "Email & Collaboration", "https://www.zendesk.com"),
    (r"teamwork-site-verification=",                               "Teamwork",               "Email & Collaboration", "https://www.teamwork.com"),
    (r"smartsheet-site-validation=",                               "Smartsheet",             "Email & Collaboration", "https://www.smartsheet.com"),

    # --- Email Deliverability / Security ---
    (r"include:sendgrid\.net",                                     "SendGrid",               "Email Deliverability",  "https://sendgrid.com"),
    (r"include:spf\.mandrillapp\.com",                             "Mailchimp Transactional","Email Deliverability",  "https://mailchimp.com/features/transactional-email"),
    (r"include:mailgun\.org",                                      "Mailgun",                "Email Deliverability",  "https://www.mailgun.com"),
    (r"include:spf\.mtasv\.net",                                   "Postmark",               "Email Deliverability",  "https://postmarkapp.com"),
    (r"include:servers\.mcsv\.net",                                "Mailchimp",              "Email Deliverability",  "https://mailchimp.com"),
    (r"include:spf\.sendinblue\.com|include:spf\.brevo\.com",      "Brevo (Sendinblue)",     "Email Deliverability",  "https://www.brevo.com"),
    (r"include:_spf\.salesforce\.com",                             "Salesforce Email",       "Email Deliverability",  "https://www.salesforce.com"),
    (r"include:amazonses\.com|amazonses:",                         "Amazon SES",             "Email Deliverability",  "https://aws.amazon.com/ses"),
    (r"include:spf\.pphosted\.com",                                "Proofpoint",             "Email Security",        "https://www.proofpoint.com"),
    (r"include:.*mimecast\.com",                                   "Mimecast",               "Email Security",        "https://www.mimecast.com"),
    (r"include:.*barracuda",                                       "Barracuda Email",        "Email Security",        "https://www.barracuda.com"),
    (r"include:.*messagelabs\.com",                                "Symantec Email",         "Email Security",        "https://www.broadcom.com"),
    (r"ondmarc\.com",                                              "OnDMARC",                "Email Security",        "https://ondmarc.com"),

    # --- CRM & Marketing ---
    (r"salesforce\.com|_domainkey.*\.salesforce\.com",             "Salesforce",             "CRM & Marketing",       "https://www.salesforce.com"),
    (r"hubspot-developer-verification=|hs-site-verification",      "HubSpot",                "CRM & Marketing",       "https://www.hubspot.com"),
    (r"include:email\.freshdesk\.com",                             "Freshdesk",              "CRM & Marketing",       "https://www.freshdesk.com"),
    (r"klaviyo-site-verification=",                                "Klaviyo",                "CRM & Marketing",       "https://www.klaviyo.com"),
    (r"intercom-site-verification=|intercom\.io",                  "Intercom",               "CRM & Marketing",       "https://www.intercom.com"),
    (r"marketo-domain-verification=",                              "Marketo",                "CRM & Marketing",       "https://www.marketo.com"),
    (r"pardot",                                                    "Salesforce Pardot",      "CRM & Marketing",       "https://www.salesforce.com/products/b2b-marketing-automation"),
    (r"eloqua",                                                    "Oracle Eloqua",          "CRM & Marketing",       "https://www.oracle.com/cx/marketing/automation"),
    (r"mixpanel-domain-verify=",                                   "Mixpanel",               "CRM & Marketing",       "https://mixpanel.com"),

    # --- Developer Tools ---
    (r"atlassian-domain-verification=",                            "Atlassian",              "Developer Tools",       "https://www.atlassian.com"),
    (r"status-page-domain-verification=",                          "Atlassian Statuspage",   "Developer Tools",       "https://www.atlassian.com/software/statuspage"),
    (r"_github-challenge-",                                        "GitHub",                 "Developer Tools",       "https://github.com"),
    (r"gitlab-site-verification=",                                 "GitLab",                 "Developer Tools",       "https://gitlab.com"),
    (r"bitbucket-verification=",                                   "Bitbucket",              "Developer Tools",       "https://bitbucket.org"),
    (r"postman-domain-verification=",                              "Postman",                "Developer Tools",       "https://www.postman.com"),
    (r"mongodb-site-verification=",                                "MongoDB Atlas",          "Developer Tools",       "https://www.mongodb.com/atlas"),
    (r"hcp-domain-verification=",                                  "HashiCorp Cloud",        "Developer Tools",       "https://www.hashicorp.com/cloud"),
    (r"cursor-domain-verification",                                "Cursor",                 "Developer Tools",       "https://www.cursor.com"),
    (r"docusign=",                                                 "DocuSign",               "Developer Tools",       "https://www.docusign.com"),

    # --- Payments ---
    (r"stripe-verification=",                                      "Stripe",                 "Payments",              "https://stripe.com"),

    # --- Social & Ads ---
    (r"facebook-domain-verification=",                             "Meta / Facebook",        "Social & Ads",          "https://www.facebook.com"),

    # --- SEO & Analytics ---
    (r"google-site-verification=",                                 "Google Search Console",  "SEO & Analytics",       "https://search.google.com/search-console"),

    # --- Enterprise Software ---
    (r"adobe-idp-site-verification=",                              "Adobe",                  "Enterprise Software",   "https://www.adobe.com"),
    (r"apple-domain-verification=",                                "Apple",                  "Enterprise Software",   "https://www.apple.com"),
    (r"cisco-ci-domain-verification=",                             "Cisco",                  "Enterprise Software",   "https://www.cisco.com"),
    (r"jamf-site-verification=",                                   "Jamf",                   "Enterprise Software",   "https://www.jamf.com"),
    (r"onetrust-domain-verification=",                             "OneTrust",               "Enterprise Software",   "https://www.onetrust.com"),
    (r"storiesonboard-verification=",                              "StoriesOnBoard",          "Enterprise Software",   "https://storiesonboard.com"),

    # --- Storage & Productivity ---
    (r"dropbox-domain-verification=",                              "Dropbox",                "Storage & Productivity","https://www.dropbox.com"),
    (r"box-domain-verification=",                                  "Box",                    "Storage & Productivity","https://www.box.com"),
    (r"notion-domain-verification=",                               "Notion",                 "Storage & Productivity","https://www.notion.so"),

    # --- Identity & Security ---
    (r"include:.*okta\.com",                                       "Okta",                   "Identity & SSO",        "https://www.okta.com"),
    (r"include:.*onelogin\.com",                                   "OneLogin",               "Identity & SSO",        "https://www.onelogin.com"),
    (r"include:.*ping\.com|pingidentity",                          "Ping Identity",          "Identity & SSO",        "https://www.pingidentity.com"),
    (r"logmein-verification=",                                     "LogMeIn",                "Remote Access",         "https://www.logmein.com"),
    (r"citrix-verification=",                                      "Citrix",                 "Remote Access",         "https://www.citrix.com"),
    (r"knowbe4-site-verification=",                                "KnowBe4",                "Identity & SSO",        "https://www.knowbe4.com"),

    # --- AI ---
    (r"openai-domain-verification=",                               "OpenAI",                 "AI",                    "https://openai.com"),
    (r"anthropic-domain-verification",                             "Anthropic",              "AI",                    "https://www.anthropic.com"),

    # --- Monitoring & Analytics ---
    (r"include:.*sparkpostmail\.com",                              "SparkPost",              "Email Deliverability",  "https://www.sparkpost.com"),
    (r"datadog-site-verification=",                                "Datadog",                "Monitoring",            "https://www.datadoghq.com"),
    (r"newrelic-site-verification=",                               "New Relic",              "Monitoring",            "https://newrelic.com"),
    (r"dynatrace-site-verification=",                              "Dynatrace",              "Monitoring",            "https://www.dynatrace.com"),
]

# Deduplicate by service name (same service can match multiple patterns)
_COMPILED = [(re.compile(pat, re.IGNORECASE), name, cat, url) for pat, name, cat, url in _RULES]


def run(txt_records: list[str]) -> dict:
    """Detect SaaS services from a list of TXT record strings."""
    detected: dict[str, dict] = {}  # keyed by service name to deduplicate

    for record in txt_records:
        if record.startswith("ERROR:"):
            continue
        for pattern, name, category, url in _COMPILED:
            if name in detected:
                continue
            if pattern.search(record):
                detected[name] = {
                    "name": name,
                    "category": category,
                    "url": url,
                    "matched_record": record[:120] + ("…" if len(record) > 120 else ""),
                }

    # Group by category, sorted
    by_category: dict[str, list] = {}
    for svc in sorted(detected.values(), key=lambda x: (x["category"], x["name"])):
        by_category.setdefault(svc["category"], []).append(svc)

    return {
        "services": list(detected.values()),
        "by_category": by_category,
        "count": len(detected),
    }
