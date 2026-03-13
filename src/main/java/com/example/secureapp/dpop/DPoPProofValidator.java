package com.example.secureapp.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;

/**
 * Validates a DPoP proof JWT according to RFC 9449.
 *
 * <p>Validation steps performed:
 * <ol>
 *   <li>Parse the compact-serialised JWT</li>
 *   <li>Verify header type is {@code dpop+jwt}</li>
 *   <li>Verify algorithm is ES256 (ECDSA P-256)</li>
 *   <li>Extract the JWK public key from the header</li>
 *   <li>Verify the JWT signature using the embedded public key</li>
 *   <li>Validate the {@code htm} (HTTP method) claim</li>
 *   <li>Validate the {@code htu} (HTTP URI) claim</li>
 *   <li>Validate the {@code iat} (issued-at) claim is within the allowed window</li>
 *   <li>Validate the {@code jti} claim is present</li>
 * </ol>
 */
@Component
public class DPoPProofValidator {

    private static final Logger logger = LoggerFactory.getLogger(DPoPProofValidator.class);

    /**
     * Result object returned on successful validation.
     */
    public record DPoPValidationResult(
            ECKey publicKey,
            String jwkThumbprint,
            String jti
    ) {}

    /**
     * Parses and fully validates a DPoP proof JWT.
     *
     * @param dpopProof      the compact-serialised DPoP proof JWT
     * @param expectedMethod the HTTP method of the current request (e.g. "POST")
     * @param expectedUri    the full request URI (e.g. "https://api.example.com/api/auth/login")
     * @return a {@link DPoPValidationResult} on success
     * @throws DPoPValidationException if any validation step fails
     */
    public DPoPValidationResult validate(String dpopProof, String expectedMethod, String expectedUri) {
        try {
            // ── 1. Parse the JWT ───────────────────────────────────────────
            SignedJWT signedJWT = SignedJWT.parse(dpopProof);
            JWSHeader header = signedJWT.getHeader();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // ── 2. Verify typ = dpop+jwt ───────────────────────────────────
            if (header.getType() == null ||
                    !DPoPConstants.DPOP_TOKEN_TYPE.equalsIgnoreCase(header.getType().getType())) {
                throw new DPoPValidationException("Invalid DPoP proof: typ must be 'dpop+jwt'");
            }

            // ── 3. Verify algorithm is ES256 ───────────────────────────────
            if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
                throw new DPoPValidationException(
                        "Invalid DPoP proof: algorithm must be ES256, got " + header.getAlgorithm());
            }

            // ── 4. Extract the JWK public key from the header ─────────────
            JWK jwk = header.getJWK();
            if (jwk == null) {
                throw new DPoPValidationException("Invalid DPoP proof: missing jwk in header");
            }
            if (!(jwk instanceof ECKey ecKey)) {
                throw new DPoPValidationException("Invalid DPoP proof: jwk must be an EC key");
            }
            if (ecKey.isPrivate()) {
                throw new DPoPValidationException("Invalid DPoP proof: jwk must not contain private key");
            }

            // ── 5. Verify signature ───────────────────────────────────────
            JWSVerifier verifier = new ECDSAVerifier(ecKey);
            if (!signedJWT.verify(verifier)) {
                throw new DPoPValidationException("Invalid DPoP proof: signature verification failed");
            }

            // ── 6. Validate htm (HTTP method) ─────────────────────────────
            String htm = claims.getStringClaim(DPoPConstants.CLAIM_HTM);
            if (htm == null || !htm.equalsIgnoreCase(expectedMethod)) {
                throw new DPoPValidationException(
                        "Invalid DPoP proof: htm mismatch. Expected=" + expectedMethod + ", got=" + htm);
            }

            // ── 7. Validate htu (HTTP URI) ────────────────────────────────
            String htu = claims.getStringClaim(DPoPConstants.CLAIM_HTU);
            if (htu == null || !normalizeUri(htu).equals(normalizeUri(expectedUri))) {
                throw new DPoPValidationException(
                        "Invalid DPoP proof: htu mismatch. Expected=" + expectedUri + ", got=" + htu);
            }

            // ── 8. Validate iat (issued at) ───────────────────────────────
            if (claims.getIssueTime() == null) {
                throw new DPoPValidationException("Invalid DPoP proof: missing iat claim");
            }
            long iatEpoch = claims.getIssueTime().toInstant().getEpochSecond();
            long now = Instant.now().getEpochSecond();
            long diff = Math.abs(now - iatEpoch);
            if (diff > DPoPConstants.MAX_PROOF_AGE_SECONDS) {
                throw new DPoPValidationException(
                        "Invalid DPoP proof: proof expired or too far in the future (drift=" + diff + "s)");
            }

            // ── 9. Validate jti ────────────────────────────────────────────
            String jti = claims.getJWTID();
            if (jti == null || jti.isBlank()) {
                throw new DPoPValidationException("Invalid DPoP proof: missing jti claim");
            }

            // ── 10. Compute JWK thumbprint ────────────────────────────────
            Base64URL thumbprint = ecKey.computeThumbprint();
            String thumbprintStr = thumbprint.toString();

            logger.debug("DPoP proof validated successfully. JWK thumbprint: {}", thumbprintStr);

            return new DPoPValidationResult(ecKey, thumbprintStr, jti);

        } catch (ParseException e) {
            throw new DPoPValidationException("Invalid DPoP proof: failed to parse JWT — " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw new DPoPValidationException("Invalid DPoP proof: JOSE error — " + e.getMessage(), e);
        }
    }

    /**
     * Normalises a URI for comparison by stripping query and fragment components
     * and removing a trailing slash.
     */
    private String normalizeUri(String uri) {
        if (uri == null) return "";
        // Strip query string and fragment
        int queryIdx = uri.indexOf('?');
        if (queryIdx >= 0) uri = uri.substring(0, queryIdx);
        int fragIdx = uri.indexOf('#');
        if (fragIdx >= 0) uri = uri.substring(0, fragIdx);
        // Remove trailing slash
        if (uri.endsWith("/")) uri = uri.substring(0, uri.length() - 1);
        return uri;
    }
}
