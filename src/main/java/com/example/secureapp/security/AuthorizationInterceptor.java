package com.example.secureapp.security;

import com.example.secureapp.util.SecurityUtils;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Enterprise-grade Authorization Interceptor.
 *
 * <p>Request flow:
 * Browser → NGINX → Spring Security Filter Chain → SessionValidationFilter
 * → <b>AuthorizationInterceptor</b> → Controller
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Intercepts every request after authentication (post-filter-chain)</li>
 *   <li>Determines the API path being accessed</li>
 *   <li>Fetches the logged-in user and their roles</li>
 *   <li>Validates whether the user's role(s) have permission to access the API
 *       using the centralized {@link RolePermissionMapping}</li>
 *   <li>Logs every authorization decision with User, Role, Endpoint, and Result</li>
 *   <li>Returns HTTP 403 with a consistent JSON error body if access is denied</li>
 * </ul>
 *
 * <p>Thread-safety: This interceptor is stateless — no request-specific data
 * is stored in instance fields. All data is scoped to method-local variables.
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    private final RolePermissionMapping rolePermissionMapping;
    private final ObjectMapper objectMapper;

    public AuthorizationInterceptor(RolePermissionMapping rolePermissionMapping,
                                    ObjectMapper objectMapper) {
        this.rolePermissionMapping = rolePermissionMapping;
        this.objectMapper = objectMapper;
    }

    /**
     * Pre-handle authorization check. Runs before the controller method.
     *
     * @return true if the user is authorized, false if access is denied
     */
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        // --- Step 1: Determine the API path (servlet-relative, without context path) ---
        String path = request.getServletPath();

        // --- Step 2: Retrieve the authenticated user and roles ---
        String username = SecurityUtils.getCurrentUser().orElse("anonymous");
        Set<String> userRoles = SecurityUtils.getCurrentUserRoles();

        // --- Step 3: Fetch the allowed roles for this path ---
        List<String> allowedRoles = rolePermissionMapping.getAllowedRoles(path);

        // --- Step 4: If no explicit mapping exists, allow (defer to Spring Security) ---
        if (allowedRoles.isEmpty()) {
            logAuthorizationDecision(username, userRoles, path, "ALLOWED (no explicit restriction)");
            return true;
        }

        // --- Step 5: Check if any of the user's roles match the allowed roles ---
        boolean authorized = userRoles.stream().anyMatch(allowedRoles::contains);

        if (authorized) {
            logAuthorizationDecision(username, userRoles, path, "ALLOWED");
            return true;
        }

        // --- Step 6: Access denied — log and respond with 403 ---
        logAuthorizationDecision(username, userRoles, path, "DENIED");
        writeForbiddenResponse(response, "Access denied");
        return false;
    }

    /**
     * Logs the authorization decision in a structured format.
     * Thread-safe: all parameters are method-local.
     */
    private void logAuthorizationDecision(String username, Set<String> roles,
                                          String endpoint, String result) {
        logger.info("Authorization | User: {} | Role: {} | Endpoint: {} | Result: {}",
                username, roles, endpoint, result);
    }

    /**
     * Writes a consistent JSON 403 Forbidden response.
     * Thread-safe: all data is local to this method invocation.
     */
    private void writeForbiddenResponse(HttpServletResponse response, String message)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
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
