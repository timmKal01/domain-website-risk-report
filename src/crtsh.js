const UA = 'DomainWebsiteRiskReport/0.1 (+contact: domain-risk-report-admin@example.com)';

const TRANSIENT_STATUSES = new Set([404, 502, 503, 504]);
const MAX_ATTEMPTS = 8;
const MAX_BACKOFF_MS = 8000;
const REQUEST_TIMEOUT_MS = 25000;

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * crt.sh is a free community service that returns bare error pages (HTML, not JSON) under load :
 * observed as both 404 and 502 for the *same* query on different attempts, so these are not a
 * reliable "zero results" signal. Retry transient-looking failures instead of treating them as
 * empty results. Same retry budget as certificate-transparency-monitor, tuned there against real
 * crt.sh outages: see that actor's crtsh.js for the incident history behind these numbers.
 */
async function fetchWithRetry(url) {
    let lastError;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        let res;
        try {
            res = await fetch(url, { headers: { 'User-Agent': UA }, signal: controller.signal });
        } catch (err) {
            lastError = err.name === 'AbortError'
                ? new Error(`crt.sh request timed out after ${REQUEST_TIMEOUT_MS}ms`)
                : err;
            if (attempt < MAX_ATTEMPTS) {
                await sleep(Math.min(1000 * 2 ** (attempt - 1), MAX_BACKOFF_MS));
            }
            continue;
        } finally {
            clearTimeout(timeoutId);
        }
        if (res.ok) return res;
        if (!TRANSIENT_STATUSES.has(res.status)) {
            throw new Error(`crt.sh request failed: ${res.status}`);
        }
        lastError = new Error(`crt.sh request failed: ${res.status}`);
        if (attempt < MAX_ATTEMPTS) {
            await sleep(Math.min(1000 * 2 ** (attempt - 1), MAX_BACKOFF_MS));
        }
    }
    throw new Error(`crt.sh unavailable after ${MAX_ATTEMPTS} attempts: ${lastError.message}`);
}

export async function fetchCertificates({ domain, startDate, maxResults }) {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired`;
    const res = await fetchWithRetry(url);
    const entries = await res.json();

    const bySerial = new Map();
    for (const e of entries) {
        if (!bySerial.has(e.serial_number)) bySerial.set(e.serial_number, e);
    }

    return [...bySerial.values()]
        .filter((e) => new Date(e.not_before) >= startDate)
        .sort((a, b) => new Date(b.not_before) - new Date(a.not_before))
        .slice(0, maxResults)
        .map((e) => ({
            commonName: e.common_name,
            subjectAlternativeNames: [...new Set((e.name_value ?? '').split('\n').filter(Boolean))],
            issuerName: e.issuer_name,
            notBefore: e.not_before,
            notAfter: e.not_after,
        }));
}
