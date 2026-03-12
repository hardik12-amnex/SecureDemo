package com.example.secureapp.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Thread-safe utility class for retrieving authenticated user information
 * from the Spring Security context and HTTP session.
 *
 * <p>All methods are static and stateless — no instance fields store
 * request-specific data, ensuring complete thread safety.
 */
public final class SecurityUtils {

    private SecurityUtils() {
        // Prevent instantiation — utility class
    }

    /**
     * Retrieves the username of the currently authenticated user from the SecurityContext.
     *
     * @return an Optional containing the username, or empty if not authenticated
     */
    public static Optional<String> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getPrincipal())) {
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            return Optional.of(userDetails.getUsername());
        } else if (principal instanceof String username) {
            return Optional.of(username);
        }

        return Optional.empty();
    }

    /**
     * Retrieves the username from the HTTP session.
     *
     * @param request the current HTTP request
     * @return an Optional containing the username, or empty if session/attribute is missing
     */
    public static Optional<String> getCurrentUserFromSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Optional.empty();
        }
        Object username = session.getAttribute("username");
        return username != null ? Optional.of(username.toString()) : Optional.empty();
    }

    /**
     * Retrieves the set of role names for the currently authenticated user.
     *
     * @return a set of role names (e.g., "ROLE_ADMIN", "ROLE_USER"), or empty set
     */
    public static Set<String> getCurrentUserRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Collections.emptySet();
        }

        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    /**
     * Retrieves the roles stored in the HTTP session.
     *
     * @param request the current HTTP request
     * @return a set of role names from session, or empty set
     */
    @SuppressWarnings("unchecked")
    public static Set<String> getRolesFromSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return Collections.emptySet();
        }
        Object roles = session.getAttribute("roles");
        if (roles instanceof Set<?>) {
            return (Set<String>) roles;
        }
        return Collections.emptySet();
    }

    /**
     * Checks if the currently authenticated user has a specific role.
     *
     * @param role the role name to check (e.g., "ROLE_ADMIN")
     * @return true if the user has the role, false otherwise
     */
    public static boolean hasRole(String role) {
        return getCurrentUserRoles().contains(role);
    }

    /**
     * Checks whether the current request has an authenticated (non-anonymous) user.
     *
     * @return true if a real user is authenticated
     */
    public static boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
                && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal());
    }
}
