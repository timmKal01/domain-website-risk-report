# Domain & Website Risk Report: Expiration, SSL, Subdomains & Tech Stack

Give it a domain. Get back one combined report, covering registration and
expiration status, SSL certificate health, subdomains discovered via
Certificate Transparency logs, the live site's detected tech stack, and a
short list of computed risk flags: everything you'd otherwise check across
four separate tools, in one call.

## Who this is for

- **Security and IT teams** doing a quick external risk pass on a domain: their own, or before onboarding a vendor.
- **M&A and vendor-risk due diligence** checking a target company's web presence health without four separate lookups.
- **Agencies and consultants** auditing a client's or prospect's domain before a pitch.

## Input

| Field | Type | Description |
|---|---|---|
| `domains` | array | Bare domains, e.g. `["example.com"]`: not full URLs. |
| `includeTechStack` | boolean (default `true`) | Fetch the homepage and detect CMS, ecommerce, JS framework, analytics, CDN, payment, and live-chat signatures. |
| `includeSubdomains` | boolean (default `true`) | Search Certificate Transparency logs for subdomains. |
| `maxSubdomains` | integer (default `20`) | Cap on discovered subdomains returned. |
| `ctDaysBack` | integer (default `365`) | How far back to search Certificate Transparency logs. |

```json
{
  "domains": ["example.com"]
}
```

## Output

One record per domain:

```json
{
  "domain": "example.com",
  "registration": {
    "registered": true,
    "registrar": "Example Registrar, Inc.",
    "creationDate": "1995-08-14T04:00:00Z",
    "expirationDate": "2027-08-13T04:00:00Z",
    "daysUntilExpiration": 328,
    "nameservers": ["a.iana-servers.net", "b.iana-servers.net"]
  },
  "ssl": {
    "reachable": true,
    "subjectCN": "example.com",
    "issuerCN": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "validTo": "2027-01-15T23:59:59.000Z",
    "daysUntilExpiration": 118,
    "isExpired": false,
    "isSelfSigned": false,
    "trustedByNode": true
  },
  "subdomains": {
    "discovered": ["www.example.com", "mail.example.com"],
    "totalCertificatesFound": 14
  },
  "techStack": {
    "reachable": true,
    "detected": { "cdnHosting": ["Cloudflare"], "analytics": [], "cms": [] },
    "server": "cloudflare"
  },
  "riskFlags": [],
  "checkedAt": "2026-09-19T12:00:00.000Z"
}
```

`riskFlags` is a short list of plain-text flags computed from the other
sections: e.g. `ssl-certificate-expires-within-30-days`,
`domain-registration-expired`, `ssl-certificate-self-signed`,
`https-unreachable`. An empty array means nothing flagged.

## How it works

Four independent, direct checks per domain, no scraping beyond the site's
own homepage and no proxy:

1. **RDAP** (the modern WHOIS replacement) for registration/expiration.
2. **A direct TLS handshake** against port 443 for certificate health and trust chain validation.
3. **crt.sh** (public Certificate Transparency log search) for subdomain discovery.
4. **One fetch of the domain's own homepage** for tech-stack signature detection: same signature set as [Website Tech Stack Detector](https://github.com/timmKal01/website-tech-stack-detector).

Each check runs independently and reports its own failure without failing
the others: e.g. a domain with no live website still gets a full
registration and SSL report, with `techStack.reachable: false`.

## Related products

- [Domain Expiration Tracker](https://github.com/timmKal01/domain-expiration-tracker): registration/expiration only, for bulk monitoring across many domains
- [SSL Certificate Expiry Checker](https://github.com/timmKal01/ssl-certificate-expiry-checker): certificate health only, any host:port
- [Certificate Transparency Monitor](https://github.com/timmKal01/certificate-transparency-monitor): raw CT log search with more filtering options
- [Website Tech Stack Detector](https://github.com/timmKal01/website-tech-stack-detector): tech-stack detection across multiple URLs/pages, not scoped to one domain's risk profile
