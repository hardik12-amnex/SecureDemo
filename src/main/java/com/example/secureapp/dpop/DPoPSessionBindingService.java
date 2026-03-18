package com.example.secureapp.dpop;

import com.nimbusds.jose.jwk.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service that validates a DPoP proof at login time and returns the
 * public key thumbprint to be embedded in the JWT access token.
 *
 * <p>In the stateless architecture, instead of binding the DPoP key to a
 * server-side session, the JWK thumbprint is embedded in the JWT token
 * as the {@code dpop_jkt} claim (RFC 9449 §6). This allows the
 * {@link DPoPAuthenticationFilter} to verify proof-of-possession on
 * every request without any server-side state.</p>
 */
@Service
public class DPoPSessionBindingService {

    private static final Logger logger = LoggerFactory.getLogger(DPoPSessionBindingService.class);

    private final DPoPProofValidator proofValidator;

    public DPoPSessionBindingService(DPoPProofValidator proofValidator) {
        this.proofValidator = proofValidator;
    }

    /**
     * Validates the DPoP proof supplied during login and returns the JWK thumbprint
     * to be embedded in the JWT access token.
     *
     * @param dpopProof   the compact-serialised DPoP proof JWT from the {@code DPoP} header
     * @param httpMethod  HTTP method of the login request (e.g. "POST")
     * @param requestUri  full URI of the login request
     * @return the JWK thumbprint of the client's public key
     * @throws DPoPValidationException if the proof is invalid
     */
    public String validateAndGetThumbprint(String dpopProof, String httpMethod, String requestUri) {
        DPoPProofValidator.DPoPValidationResult result = proofValidator.validate(dpopProof, httpMethod, requestUri);

        ECKey publicKey = result.publicKey();
        String thumbprint = result.jwkThumbprint();

        logger.info("DPoP proof validated at login. JWK thumbprint: {}", thumbprint);
        return thumbprint;
    }
}