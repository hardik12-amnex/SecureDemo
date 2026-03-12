package com.example.secureapp.security;

import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Centralized role-permission mapping for API authorization.
 *
 * <p>This component maps API path patterns to the list of roles that are
 * permitted to access them. It uses {@link AntPathMatcher} for flexible
 * Ant-style path matching (e.g., {@code /admin/**}).
 *
 * <p>Thread-safety: The permission map is initialized once at construction
 * time and never modified thereafter (effectively immutable).
 */
@Component
public class RolePermissionMapping {

    private final Map<String, List<String>> permissionMap;
    private final AntPathMatcher pathMatcher;

    public RolePermissionMapping() {
        this.pathMatcher = new AntPathMatcher();

        // Build the permission map — order matters for first-match semantics
        Map<String, List<String>> map = new LinkedHashMap<>();

        // Admin-only endpoints
        map.put("/admin/**", List.of("ROLE_ADMIN"));
        map.put("/activity/admin/**", List.of("ROLE_ADMIN"));

        // User + Admin endpoints
        map.put("/activity/profile/**", List.of("ROLE_USER", "ROLE_ADMIN"));
        map.put("/activity/action/**", List.of("ROLE_USER", "ROLE_ADMIN"));

        // Dashboard — any authenticated user
        map.put("/dashboard/**", List.of("ROLE_USER", "ROLE_ADMIN"));

        this.permissionMap = Collections.unmodifiableMap(map);
    }

    /**
     * Returns the list of roles allowed for the given API path.
     *
     * @param path the servlet-relative request path (without context path)
     * @return the list of allowed roles, or an empty list if no specific rule is defined
     *         (which means the path is governed only by Spring Security's default rules)
     */
    public List<String> getAllowedRoles(String path) {
        for (Map.Entry<String, List<String>> entry : permissionMap.entrySet()) {
            if (pathMatcher.match(entry.getKey(), path)) {
                return entry.getValue();
            }
        }
        // No explicit mapping found — path is not restricted by the interceptor.
        // Spring Security's own authorization rules still apply.
        return Collections.emptyList();
    }

    /**
     * Checks whether a specific role is allowed to access the given path.
     *
     * @param path the servlet-relative request path
     * @param role the role to check (e.g., "ROLE_ADMIN")
     * @return true if allowed or no explicit restriction exists, false if denied
     */
    public boolean isRoleAllowed(String path, String role) {
        List<String> allowedRoles = getAllowedRoles(path);
        // If no explicit mapping exists, allow (defer to Spring Security)
        if (allowedRoles.isEmpty()) {
            return true;
        }
        return allowedRoles.contains(role);
    }

    /**
     * Returns an unmodifiable view of the full permission map for debugging/logging.
     */
    public Map<String, List<String>> getPermissionMap() {
        return permissionMap;
    }
}
