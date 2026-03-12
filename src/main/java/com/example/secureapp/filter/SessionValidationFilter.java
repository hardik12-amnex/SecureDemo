package com.example.secureapp.filter;

import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Enterprise-grade Session Validation Filter.
 *
 * <p>Request flow:
 * Browser → NGINX → Spring Security Filter Chain → <b>SessionValidationFilter</b>
 * → Custom Authorization Interceptor → Controller
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Validates that an HTTP session exists and is not expired</li>
 *   <li>Validates that an authenticated user object exists in the session/SecurityContext</li>
 *   <li>Returns HTTP 401 with a consistent JSON error if validation fails</li>
 *   <li>Allows the request to proceed through the filter chain when valid</li>
 * </ul>
 *
 * <p>Thread-safety: This filter is stateless — no request-specific data is stored
 * in instance fields. All data is scoped to local variables within the filter method.
 */
@Component
public class SessionValidationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionValidationFilter.class);

    private final ObjectMapper objectMapper;

    /**
     * Paths that are excluded from session validation (public endpoints).
     * These must match the servlet-relative paths (without the context path).
     */
    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/auth/login",
            "/auth/register",
            "/auth/logout",
            "/health"
    );

    public SessionValidationFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Skip this filter for public endpoints that don't require session validation.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // getServletPath() returns the path relative to the context path
        String path = request.getServletPath();
        return EXCLUDED_PATHS.stream().anyMatch(path::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // --- Step 1: Validate that a session exists (do not create a new one) ---
        HttpSession session = request.getSession(false);
        if (session == null) {
            logger.warn("Session validation failed: No session found for request [{}]", request.getServletPath());
            writeUnauthorizedResponse(response, "Session invalid or expired");
            return;
        }

        // --- Step 2: Validate that the session has not expired ---
        // For JDBC-backed sessions, getLastAccessedTime() combined with maxInactiveInterval is
        // used by the container. If session.isNew() == false and we got here, the session is
        // technically still alive, but we add an explicit time-based check for defense in depth.
        try {
            long lastAccessed = session.getLastAccessedTime();
            int maxInactive = session.getMaxInactiveInterval();
            if (maxInactive > 0) {
                long expirationTime = lastAccessed + ((long) maxInactive * 1000);
                if (System.currentTimeMillis() > expirationTime) {
                    logger.warn("Session validation failed: Session expired for request [{}]", request.getServletPath());
                    session.invalidate();
                    writeUnauthorizedResponse(response, "Session invalid or expired");
                    return;
                }
            }
        } catch (IllegalStateException ex) {
            // Session was already invalidated
            logger.warn("Session validation failed: Session already invalidated for request [{}]", request.getServletPath());
            writeUnauthorizedResponse(response, "Session invalid or expired");
            return;
        }

        // --- Step 3: Validate that an authenticated user exists in the security context ---
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getPrincipal())) {
            logger.warn("Session validation failed: No authenticated user for request [{}]", request.getServletPath());
            writeUnauthorizedResponse(response, "Session invalid or expired");
            return;
        }

        // --- Step 4: Validate that session attributes contain user data ---
        Object username = session.getAttribute("username");
        if (username == null) {
            logger.warn("Session validation failed: No username attribute in session for request [{}]", request.getServletPath());
            writeUnauthorizedResponse(response, "Session invalid or expired");
            return;
        }

        logger.debug("Session validation passed for user [{}] on [{}]", username, request.getServletPath());

        // --- Session is valid — continue the filter chain ---
        filterChain.doFilter(request, response);
    }

    /**
     * Writes a consistent JSON 401 Unauthorized response.
     * Thread-safe: all data is local to this method invocation.
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
