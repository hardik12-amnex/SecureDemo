package com.example.secureapp.dpop;

import com.example.secureapp.filter.JwtAuthenticationFilter;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * DPoP (Demonstration of Proof-of-Possession) Authentication Filter.
 *
 * <p>This filter is placed <b>after</b> {@code JwtAuthenticationFilter}
 * in the Spring Security filter chain. It enforces that every authenticated request
 * carries a valid {@code DPoP} proof JWT whose public key matches the key bound
 * to the JWT access token at login time.</p>
 *
 * <h3>Request flow (stateless)</h3>
 * <pre>
 * Browser → Spring Security → JwtAuthenticationFilter
 *         → DPoPAuthenticationFilter → Controller
 * </pre>
 *
 * <h3>Key binding</h3>
 * <p>Instead of storing the DPoP JWK thumbprint in a server-side session, the
 * thumbprint is embedded in the JWT access token as the {@code dpop_jkt} claim
 * (RFC 9449 §6). The {@code JwtAuthenticationFilter} extracts this claim and
 * stores it as a request attribute for this filter to verify.</p>
 *
 * <h3>Excluded paths</h3>
 * <p>Login, registration, logout, and health endpoints are excluded because
 * the JWT token does not exist yet (login) or is not required (public endpoints).
 * The login endpoint performs its own DPoP handling in the controller to
 * generate the JWT with the bound public key thumbprint.</p>
 */
@Component
public class DPoPAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(DPoPAuthenticationFilter.class);

    private final DPoPProofValidator proofValidator;
    private final DPoPReplayProtectionService replayProtectionService;
    private final ObjectMapper objectMapper;

    /**
     * Paths excluded from DPoP enforcement.
     * Login is excluded because the JWT token doesn't exist yet — DPoP binding
     * is handled inside the login controller.
     */
    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/auth/login",
            "/auth/register",
            "/auth/logout",
            "/health",
            "/actuator/health"
    );

    public DPoPAuthenticationFilter(DPoPProofValidator proofValidator,
                                    DPoPReplayProtectionService replayProtectionService,
                                    ObjectMapper objectMapper) {
        this.proofValidator = proofValidator;
        this.replayProtectionService = replayProtectionService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return EXCLUDED_PATHS.stream().anyMatch(path::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // ── 1. Extract DPoP header ─────────────────────────────────────────
        String dpopProof = request.getHeader(DPoPConstants.DPOP_HEADER);
        if (dpopProof == null || dpopProof.isBlank()) {
            logger.warn("DPoP filter: Missing DPoP header on [{}] {}", request.getMethod(), request.getServletPath());
            writeUnauthorizedResponse(response, "Missing DPoP proof header");
            return;
        }

        // ── 2. Build the expected htu (full request URI) ───────────────────
        String expectedUri = buildRequestUri(request);
        String expectedMethod = request.getMethod();

        // ── 3. Validate the DPoP proof JWT ─────────────────────────────────
        DPoPProofValidator.DPoPValidationResult validationResult;
        try {
            validationResult = proofValidator.validate(dpopProof, expectedMethod, expectedUri);
        } catch (DPoPValidationException ex) {
            logger.warn("DPoP filter: Proof validation failed — {}", ex.getMessage());
            writeUnauthorizedResponse(response, ex.getMessage());
            return;
        }

        // ── 4. Replay protection — check jti uniqueness ───────────────────
        if (!replayProtectionService.isJtiUnique(validationResult.jti())) {
            logger.warn("DPoP filter: Replay detected for jti [{}]", validationResult.jti());
            writeUnauthorizedResponse(response, "DPoP proof replay detected");
            return;
        }

        // ── 5. Verify JWT-bound public key (stateless: from request attribute) ──
        // The JwtAuthenticationFilter extracts the dpop_jkt claim from the JWT
        // token and stores it as a request attribute.
        String storedThumbprint = (String) request.getAttribute(
                JwtAuthenticationFilter.REQUEST_ATTR_DPOP_THUMBPRINT);
        if (storedThumbprint == null) {
            logger.warn("DPoP filter: No DPoP thumbprint found in JWT token");
            writeUnauthorizedResponse(response, "Token not bound to DPoP key");
            return;
        }

        if (!storedThumbprint.equals(validationResult.jwkThumbprint())) {
            logger.warn("DPoP filter: JWK thumbprint mismatch. Token={}, Proof={}",
                    storedThumbprint, validationResult.jwkThumbprint());
            writeUnauthorizedResponse(response, "DPoP proof key does not match token-bound key");
            return;
        }

        logger.debug("DPoP filter: Proof validated successfully for [{}] {}",
                expectedMethod, request.getServletPath());

        // ── 6. All checks passed — continue filter chain ──────────────────
        filterChain.doFilter(request, response);
    }

    /**
     * Builds the full request URI used as the expected {@code htu} value.
     * Includes scheme, host, port (if non-standard), context path, and servlet path.
     * Query string is intentionally excluded per RFC 9449.
     */
    private String buildRequestUri(HttpServletRequest request) {
        StringBuffer url = request.getRequestURL();
        // RequestURL already includes scheme + host + port + context path + servlet path
        return url.toString();
    }

    /**
     * Writes a JSON 401 Unauthorized response consistent with the application's
     * existing error format.
     */
    private void writeUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> errorBody = new LinkedHashMap<>();
        errorBody.put("status", "ERROR");
        errorBody.put("message", message);
        errorBody.put("timestamp", Instant.now().toString());

        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
        response.getWriter().flush();
    }
}
