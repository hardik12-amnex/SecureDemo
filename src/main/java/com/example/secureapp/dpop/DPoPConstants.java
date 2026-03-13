package com.example.secureapp.dpop;

/**
 * Constants used across the DPoP (Demonstration of Proof-of-Possession) implementation.
 *
 * <p>DPoP binds an asymmetric keypair to an HTTP session so that even if a session
 * cookie is stolen, the attacker cannot forge a valid DPoP proof without the
 * client's private key.</p>
 */
public final class DPoPConstants {

    private DPoPConstants() {
        // Utility class — no instantiation
    }

    // ── Header & Token Type ────────────────────────────────────────────────
    /** HTTP header name carrying the DPoP proof JWT. */
    public static final String DPOP_HEADER = "DPoP";

    /** Expected "typ" value in the DPoP proof JWT header (RFC 9449 §4.2). */
    public static final String DPOP_TOKEN_TYPE = "dpop+jwt";

    // ── JWT Claims ─────────────────────────────────────────────────────────
    /** Claim for the HTTP method the proof is bound to. */
    public static final String CLAIM_HTM = "htm";

    /** Claim for the HTTP URI the proof is bound to. */
    public static final String CLAIM_HTU = "htu";

    /** Standard JWT ID claim used for replay protection. */
    public static final String CLAIM_JTI = "jti";

    /** Standard "issued at" claim. */
    public static final String CLAIM_IAT = "iat";

    // ── Session Attributes ─────────────────────────────────────────────────
    /** Session attribute key storing the JWK thumbprint of the bound public key. */
    public static final String SESSION_ATTR_DPOP_JWK_THUMBPRINT = "DPOP_JWK_THUMBPRINT";

    /** Session attribute key storing the serialised JWK public key JSON. */
    public static final String SESSION_ATTR_DPOP_PUBLIC_KEY = "DPOP_PUBLIC_KEY";

    // ── Validation Limits ──────────────────────────────────────────────────
    /** Maximum allowed clock skew / proof age in seconds (5 minutes). */
    public static final long MAX_PROOF_AGE_SECONDS = 300L;

    /** TTL for JTI cache entries in seconds (matches proof age). */
    public static final long JTI_CACHE_TTL_SECONDS = 300L;

    /** Maximum number of JTI entries kept in the replay-protection cache. */
    public static final long JTI_CACHE_MAX_SIZE = 100_000L;
}
