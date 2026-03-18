package com.example.secureapp.filter;

import com.example.secureapp.controller.AuthController;
import com.example.secureapp.security.JwtTokenService;
import tools.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * JWT Authentication Filter — Stateless Token Validation via HttpOnly Cookie.
 *
 * <p>This filter extracts the JWT access token from the {@code ACCESS_TOKEN}
 * HttpOnly cookie (set by the login endpoint). The cookie is automatically
 * attached by the browser on every request, and is inaccessible to JavaScript
 * (XSS-proof).</p>
 *
 * <p>The server remains fully stateless — no session state is stored. The cookie
 * is merely a secure transport mechanism for the self-contained JWT token.</p>
 *
 * <p>Request flow:
 * Browser → Spring Security Filter Chain → <b>JwtAuthenticationFilter</b>
 * → DPoPAuthenticationFilter → AuthorizationInterceptor → Controller</p>
 *
 * <p>Responsibilities:</p>
 * <ul>
 *   <li>Extracts the JWT token from the {@code ACCESS_TOKEN} HttpOnly cookie</li>
 *   <li>Validates the token signature, expiry, and issuer</li>
 *   <li>Extracts user identity and roles from the token claims</li>
 *   <li>Sets the Spring Security {@code Authentication} in the {@code SecurityContext}</li>
 *   <li>Stores the DPoP JWK thumbprint as a request attribute for downstream filters</li>
 * </ul>
 *
 * <p>Thread-safety: This filter is stateless — no request-specific data is stored
 * in instance fields.</p>
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /** Request attribute key for storing the DPoP JWK thumbprint from the JWT token. */
    public static final String REQUEST_ATTR_DPOP_THUMBPRINT = "DPOP_JWK_THUMBPRINT";

    /** Request attribute key for storing the user ID from the JWT token. */
    public static final String REQUEST_ATTR_USER_ID = "userId";

    private final JwtTokenService jwtTokenService;
    private final ObjectMapper objectMapper;

    /**
     * Paths excluded from JWT authentication (public endpoints).
     */
    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/auth/login",
            "/auth/register",
            "/auth/logout",
            "/health"
    );

    public JwtAuthenticationFilter(JwtTokenService jwtTokenService, ObjectMapper objectMapper) {
        this.jwtTokenService = jwtTokenService;
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

        // ── 1. Extract JWT from HttpOnly cookie ────────────────────────────
        String token = extractTokenFromCookie(request);
        if (token == null) {
            logger.warn("JWT filter: Missing ACCESS_TOKEN cookie on [{}] {}",
                    request.getMethod(), request.getServletPath());
            writeUnauthorizedResponse(response, "Missing authentication token");
            return;
        }

        // ── 2. Validate JWT token ──────────────────────────────────────────
        Claims claims;
        try {
            claims = jwtTokenService.validateAndGetClaims(token);
        } catch (JwtException ex) {
            logger.warn("JWT filter: Token validation failed — {}", ex.getMessage());
            writeUnauthorizedResponse(response, "Invalid or expired token");
            return;
        }

        // ── 3. Extract user information from claims ────────────────────────
        String username = claims.getSubject();
        if (username == null || username.isBlank()) {
            logger.warn("JWT filter: Token has no subject claim");
            writeUnauthorizedResponse(response, "Invalid token: missing subject");
            return;
        }

        @SuppressWarnings("unchecked")
        List<String> roles = claims.get("roles", List.class);
        Long userId = claims.get("userId", Long.class);
        String dpopThumbprint = claims.get("dpop_jkt", String.class);

        // ── 4. Set Authentication in SecurityContext ───────────────────────
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            List<SimpleGrantedAuthority> authorities = roles != null
                    ? roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                    : List.of();

            UserDetails userDetails = new User(username, "", authorities);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("JWT filter: Authentication set for user [{}] with roles {}", username, roles);
        }

        // ── 5. Store DPoP thumbprint and userId as request attributes ──────
        // These are used by DPoPAuthenticationFilter and controllers
        if (dpopThumbprint != null) {
            request.setAttribute(REQUEST_ATTR_DPOP_THUMBPRINT, dpopThumbprint);
        }
        if (userId != null) {
            request.setAttribute(REQUEST_ATTR_USER_ID, userId);
        }

        // ── 6. Continue filter chain ───────────────────────────────────────
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts the JWT token from the {@code ACCESS_TOKEN} HttpOnly cookie.
     *
     * @param request the HTTP request
     * @return the JWT token string, or {@code null} if the cookie is not present
     */
    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (AuthController.JWT_COOKIE_NAME.equals(cookie.getName())) {
                String value = cookie.getValue();
                return (value != null && !value.isBlank()) ? value : null;
            }
        }
        return null;
    }

    /**
     * Writes a consistent JSON 401 Unauthorized response.
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
