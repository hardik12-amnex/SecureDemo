package com.example.secureapp.dpop;

import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service that binds a DPoP public key to an HTTP session at login time.
 *
 * <p>Called from the login controller after successful authentication.  The
 * client's EC P-256 public key (extracted from the DPoP proof JWT header) is
 * stored in the session as two attributes:</p>
 * <ul>
 *   <li>{@link DPoPConstants#SESSION_ATTR_DPOP_PUBLIC_KEY} — serialised JWK JSON
 *       (useful for debugging / auditing)</li>
 *   <li>{@link DPoPConstants#SESSION_ATTR_DPOP_JWK_THUMBPRINT} — JWK thumbprint
 *       (used for fast comparison in the filter)</li>
 * </ul>
 */
@Service
public class DPoPSessionBindingService {

    private static final Logger logger = LoggerFactory.getLogger(DPoPSessionBindingService.class);

    private final DPoPProofValidator proofValidator;

    public DPoPSessionBindingService(DPoPProofValidator proofValidator) {
        this.proofValidator = proofValidator;
    }

    /**
     * Validates the DPoP proof supplied during login and binds the client's
     * public key to the given session.
     *
     * @param dpopProof   the compact-serialised DPoP proof JWT from the {@code DPoP} header
     * @param httpMethod  HTTP method of the login request (e.g. "POST")
     * @param requestUri  full URI of the login request
     * @param session     the newly-created HTTP session
     * @throws DPoPValidationException if the proof is invalid
     */
    public void validateAndBindKey(String dpopProof, String httpMethod, String requestUri, HttpSession session) {
        DPoPProofValidator.DPoPValidationResult result = proofValidator.validate(dpopProof, httpMethod, requestUri);

        ECKey publicKey = result.publicKey();
        String thumbprint = result.jwkThumbprint();

        // Store public key JSON and thumbprint in the session (persisted via Spring Session JDBC)
        session.setAttribute(DPoPConstants.SESSION_ATTR_DPOP_PUBLIC_KEY, publicKey.toJSONString());
        session.setAttribute(DPoPConstants.SESSION_ATTR_DPOP_JWK_THUMBPRINT, thumbprint);

        logger.info("DPoP public key bound to session [{}]. JWK thumbprint: {}", session.getId(), thumbprint);
    }
}
