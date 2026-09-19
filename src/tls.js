import tls from 'node:tls';
import crypto from 'node:crypto';

const TIMEOUT_MS = 8000;

/** Node's own bundled root CA fingerprints, computed once so an untrusted terminal cert can be checked by identity, not by parsing an error string. */
const KNOWN_ROOT_FINGERPRINTS = new Set(
    tls.rootCertificates.map((pem) => new crypto.X509Certificate(pem).fingerprint256),
);

export function parseHostPort(entry) {
    const trimmed = entry.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const idx = trimmed.lastIndexOf(':');
    if (idx > -1 && /^\d+$/.test(trimmed.slice(idx + 1))) {
        return { host: trimmed.slice(0, idx), port: Number(trimmed.slice(idx + 1)) };
    }
    return { host: trimmed, port: 443 };
}

function parseSubjectAltNames(sanString) {
    if (!sanString) return [];
    return sanString.split(',').map((s) => s.trim());
}

function connectTls(host, port) {
    return new Promise((resolve, reject) => {
        const socket = tls.connect(
            { host, port, servername: host, timeout: TIMEOUT_MS, rejectUnauthorized: false },
            () => {
                const cert = socket.getPeerCertificate(true);
                const authorized = socket.authorized;
                const authorizationError = socket.authorizationError;
                socket.end();
                if (!cert || Object.keys(cert).length === 0) {
                    reject(new Error('No certificate returned by host'));
                    return;
                }
                resolve({ cert, authorized, authorizationError });
            },
        );
        socket.on('error', (err) => reject(err));
        socket.on('timeout', () => {
            socket.destroy();
            reject(new Error('Connection timed out'));
        });
    });
}

/**
 * Walks the chain the server actually sent, via the issuerCertificate links Node fills
 * in when getPeerCertificate is called with detailed=true, instead of parsing Node's own
 * authorizationError string. Node sets a cert's issuerCertificate to itself once the walk
 * reaches a self-signed cert; if the server's chain is missing an intermediate, the walk
 * simply runs out before ever reaching a self-signed cert.
 */
function walkChain(leafCert) {
    const chain = [];
    let current = leafCert;
    while (current && !chain.includes(current)) {
        chain.push(current);
        if (!current.issuerCertificate || current.issuerCertificate === current) break;
        current = current.issuerCertificate;
    }
    const terminal = chain[chain.length - 1];
    const chainComplete = terminal?.issuerCertificate === terminal;
    return { terminal, chainComplete };
}

/**
 * Distinguishes three genuinely different repairs that authorizationError.message alone
 * collapses into one opaque string: the leaf is self-signed (renew it), the server's chain
 * is missing an intermediate (fix what the server sends), or the chain is complete but
 * terminates at a root this Node install doesn't have bundled (a stale client trust store,
 * not a server-side problem at all).
 */
function classifyTrustFailure(cert, authorized) {
    if (authorized) return { trustFailureReason: null, chainComplete: true, terminalIssuerTrusted: true };

    const isLeafSelfSigned = cert.issuer?.CN && cert.subject?.CN && cert.issuer.CN === cert.subject.CN;
    if (isLeafSelfSigned) {
        return { trustFailureReason: 'self-signed-leaf', chainComplete: true, terminalIssuerTrusted: false };
    }

    const { terminal, chainComplete } = walkChain(cert);
    if (!chainComplete) {
        return { trustFailureReason: 'chain-incomplete', chainComplete: false, terminalIssuerTrusted: null };
    }

    const terminalIssuerTrusted = KNOWN_ROOT_FINGERPRINTS.has(terminal.fingerprint256);
    return {
        trustFailureReason: terminalIssuerTrusted ? 'other' : 'unknown-root',
        chainComplete: true,
        terminalIssuerTrusted,
    };
}

export async function checkCertificate(entry) {
    const { host, port } = parseHostPort(entry);
    const { cert, authorized, authorizationError } = await connectTls(host, port);

    const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
    const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
    const daysUntilExpiration = validTo ? Math.round((validTo.getTime() - Date.now()) / (24 * 60 * 60 * 1000)) : null;
    const { trustFailureReason, chainComplete, terminalIssuerTrusted } = classifyTrustFailure(cert, authorized);

    return {
        host,
        port,
        reachable: true,
        subjectCN: cert.subject?.CN ?? null,
        issuerCN: cert.issuer?.CN ?? null,
        issuerO: cert.issuer?.O ?? null,
        validFrom: validFrom ? validFrom.toISOString() : null,
        validTo: validTo ? validTo.toISOString() : null,
        daysUntilExpiration,
        isExpired: validTo ? validTo.getTime() < Date.now() : null,
        isSelfSigned: cert.issuer?.CN && cert.subject?.CN ? cert.issuer.CN === cert.subject.CN : null,
        trustedByNode: authorized === true,
        trustError: authorized ? null : authorizationError?.message ?? null,
        trustFailureReason,
        chainComplete,
        terminalIssuerTrusted,
        subjectAltNames: parseSubjectAltNames(cert.subjectaltname),
        fingerprint256: cert.fingerprint256 ?? null,
        error: null,
    };
}
