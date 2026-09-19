const UA = 'DomainWebsiteRiskReport/0.1 (+contact: domain-risk-report-admin@example.com)';
const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

const TRANSIENT_STATUSES = new Set([429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 4;
const REQUEST_TIMEOUT_MS = 15_000;

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(url, options) {
    let lastError;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        let res;
        try {
            res = await fetch(url, { ...options, signal: controller.signal });
        } catch (err) {
            lastError = err.name === 'AbortError' ? new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms: ${url}`) : err;
            if (attempt < MAX_ATTEMPTS) {
                await sleep(1000 * 2 ** (attempt - 1));
                continue;
            }
            throw lastError;
        } finally {
            clearTimeout(timeoutId);
        }
        if (res.status === 404 || res.ok) return res;
        if (!TRANSIENT_STATUSES.has(res.status)) {
            throw new Error(`RDAP request failed: ${res.status} ${res.statusText}`);
        }
        lastError = new Error(`RDAP request failed: ${res.status} ${res.statusText}`);
        if (attempt < MAX_ATTEMPTS) await sleep(1000 * 2 ** (attempt - 1));
    }
    throw lastError;
}

let bootstrapPromise = null;

async function loadBootstrap() {
    if (!bootstrapPromise) {
        bootstrapPromise = fetchWithRetry(BOOTSTRAP_URL, { headers: { 'User-Agent': UA } })
            .then((res) => res.json())
            .then((data) => data.services);
    }
    return bootstrapPromise;
}

async function rdapBaseUrlFor(domain) {
    const tld = domain.split('.').pop().toLowerCase();
    const services = await loadBootstrap();
    const entry = services.find((s) => s[0].includes(tld));
    if (!entry) throw new Error(`No RDAP server registered for ".${tld}" (not all TLDs support RDAP)`);
    return entry[1][0].replace(/\/$/, '');
}

function findEvent(events, action) {
    return events?.find((e) => e.eventAction === action)?.eventDate ?? null;
}

export async function lookupDomain(domain) {
    const baseUrl = await rdapBaseUrlFor(domain);
    const res = await fetchWithRetry(`${baseUrl}/domain/${encodeURIComponent(domain)}`, {
        headers: { 'User-Agent': UA, Accept: 'application/rdap+json' },
    });

    if (res.status === 404) {
        return { domain, registered: false, registrar: null, creationDate: null, expirationDate: null, daysUntilExpiration: null, lastChangedDate: null, statuses: [], nameservers: [], rdapUrl: `${baseUrl}/domain/${domain}` };
    }

    const data = await res.json();

    const registrarEntity = data.entities?.find((e) => e.roles?.includes('registrar'));
    const registrarName = registrarEntity?.vcardArray?.[1]?.find((f) => f[0] === 'fn')?.[3] ?? registrarEntity?.publicIds?.[0]?.identifier ?? null;

    const expirationDate = findEvent(data.events, 'expiration');
    const daysUntilExpiration = expirationDate
        ? Math.round((new Date(expirationDate).getTime() - Date.now()) / (24 * 60 * 60 * 1000))
        : null;

    return {
        domain,
        registered: true,
        registrar: registrarName,
        creationDate: findEvent(data.events, 'registration'),
        expirationDate,
        daysUntilExpiration,
        lastChangedDate: findEvent(data.events, 'last changed'),
        statuses: data.status ?? [],
        nameservers: (data.nameservers ?? []).map((ns) => ns.ldhName).filter(Boolean),
        rdapUrl: `${baseUrl}/domain/${domain}`,
    };
}
