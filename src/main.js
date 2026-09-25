import { Actor, log } from 'apify';
import { lookupDomain } from './rdap.js';
import { checkCertificate } from './tls.js';
import { fetchCertificates } from './crtsh.js';
import { checkTechStack } from './techstack.js';

await Actor.init();

const input = (await Actor.getInput()) ?? {};
const {
    includeTechStack = true,
    includeSubdomains = true,
    maxSubdomains = 20,
    ctDaysBack = 365,
} = input;
let { domains } = input;

/** Must match the event name configured in this Actor's pay-per-event pricing on Apify. */
const DOMAIN_REPORT_EVENT = 'domain-report';

// An empty run (first click in the Console, Apify's daily health check) used to
// throw here and got the actor flagged "under maintenance". Run the example instead.
if (domains === undefined || (Array.isArray(domains) && domains.length === 0)) {
    domains = ['apify.com'];
    log.info('No domains given; defaulting to the example "apify.com".');
}
if (!Array.isArray(domains)) {
    throw new Error('Input "domains" must be an array of domains, e.g. ["example.com"].');
}

function extractSubdomains(certificates, rootDomain, max) {
    const names = new Set();
    for (const cert of certificates) {
        for (const name of [cert.commonName, ...cert.subjectAlternativeNames]) {
            if (!name) continue;
            const clean = name.toLowerCase().replace(/^\*\./, '');
            if (clean.endsWith(`.${rootDomain}`) || clean === rootDomain) names.add(clean);
        }
    }
    return [...names].sort().slice(0, max);
}

function computeRiskFlags({ registration, ssl, techStack }) {
    const flags = [];

    if (!registration.registered) {
        flags.push('domain-not-registered');
    } else if (typeof registration.daysUntilExpiration === 'number' && registration.daysUntilExpiration <= 30) {
        flags.push(registration.daysUntilExpiration < 0 ? 'domain-registration-expired' : 'domain-expires-within-30-days');
    }

    if (!ssl.reachable) {
        flags.push('https-unreachable');
    } else {
        if (ssl.isExpired) flags.push('ssl-certificate-expired');
        else if (typeof ssl.daysUntilExpiration === 'number' && ssl.daysUntilExpiration <= 30) flags.push('ssl-certificate-expires-within-30-days');
        if (ssl.isSelfSigned) flags.push('ssl-certificate-self-signed');
        if (!ssl.trustedByNode && !ssl.isSelfSigned) flags.push(`ssl-certificate-untrusted-${ssl.trustFailureReason ?? 'unknown'}`);
    }

    if (includeTechStack && techStack && !techStack.reachable) {
        flags.push('website-unreachable');
    }

    return flags;
}

for (const rawDomain of domains) {
    const domain = rawDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    log.info(`Building risk report for ${domain}`);

    const [registration, ssl] = await Promise.all([
        lookupDomain(domain).catch((err) => {
            log.warning('RDAP lookup failed', { domain, error: err.message });
            return { domain, registered: null, error: err.message };
        }),
        checkCertificate(domain).catch((err) => ({
            host: domain, port: 443, reachable: false, error: err.message,
        })),
    ]);

    let subdomains = null;
    if (includeSubdomains) {
        try {
            const certificates = await fetchCertificates({
                domain,
                startDate: new Date(Date.now() - ctDaysBack * 24 * 60 * 60 * 1000),
                maxResults: 500,
            });
            subdomains = {
                discovered: extractSubdomains(certificates, domain, Math.min(maxSubdomains, 100)),
                totalCertificatesFound: certificates.length,
            };
        } catch (err) {
            log.warning('Certificate transparency lookup failed', { domain, error: err.message });
            subdomains = { discovered: [], totalCertificatesFound: 0, error: err.message };
        }
    }

    const techStack = includeTechStack ? await checkTechStack(domain) : null;

    const riskFlags = computeRiskFlags({ registration, ssl, techStack });

    await Actor.pushData({
        domain,
        registration,
        ssl,
        subdomains,
        techStack,
        riskFlags,
        checkedAt: new Date().toISOString(),
    });

    await Actor.charge({ eventName: DOMAIN_REPORT_EVENT });

    log.info(`Report built for ${domain}`, { riskFlagCount: riskFlags.length });
}

await Actor.exit();
