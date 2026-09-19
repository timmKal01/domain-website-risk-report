import * as cheerio from 'cheerio';
import { detectTechStack } from './signatures.js';

const REQUEST_TIMEOUT_MS = 15_000;
const UA = 'Mozilla/5.0 (compatible; DomainWebsiteRiskReport/0.1; +contact: domain-risk-report-admin@example.com)';

export async function checkTechStack(domain) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const res = await fetch(`https://${domain}/`, {
            headers: { 'User-Agent': UA },
            redirect: 'follow',
            signal: controller.signal,
        });
        const html = await res.text();
        const $ = cheerio.load(html);
        const headers = Object.fromEntries(res.headers.entries());
        const { detected, server, poweredBy, generator } = detectTechStack({ headers, html, $ });
        return { reachable: true, finalUrl: res.url, detected, server, poweredBy, generator, error: null };
    } catch (err) {
        return {
            reachable: false,
            finalUrl: null,
            detected: null,
            server: null,
            poweredBy: null,
            generator: null,
            error: err.name === 'AbortError' ? `Request timed out after ${REQUEST_TIMEOUT_MS}ms` : err.message,
        };
    } finally {
        clearTimeout(timer);
    }
}
