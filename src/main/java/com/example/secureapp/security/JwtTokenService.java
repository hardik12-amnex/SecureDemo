package com.example.secureapp.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for generating and validating JWT access tokens.
 *
 * <p>Replaces the previous session-based authentication approach with
 * stateless JWT tokens. Each token contains the user's identity, roles,
 * and the DPoP JWK thumbprint bound at login time.</p>
 *
 * <p>Token structure (claims):</p>
 * <ul>
 *   <li>{@code sub} — username</li>
 *   <li>{@code roles} — list of role names (e.g., ROLE_USER, ROLE_ADMIN)</li>
 *   <li>{@code userId} — database user ID</li>
 *   <li>{@code dpop_jkt} — DPoP JWK thumbprint (RFC 9449 confirmation)</li>
 *   <li>{@code iss} — issuer</li>
 *   <li>{@code iat} — issued at</li>
 *   <li>{@code exp} — expiration</li>
 * </ul>
 */
@Service
public class JwtTokenService {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenService.class);

    private final SecretKey signingKey;
    private final long expirationMs;
    private final String issuer;

    public JwtTokenService(
            @Value("${app.security.jwt.secret}") String secret,
            @Value("${app.security.jwt.expiration-ms}") long expirationMs,
            @Value("${app.security.jwt.issuer}") String issuer) {
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
        this.issuer = issuer;
    }

    /**
     * Generates a JWT access token for the given user with DPoP binding.
     *
     * @param userDetails     the authenticated user's details
     * @param userId          the database user ID
     * @param dpopThumbprint  the JWK thumbprint of the DPoP-bound public key
     * @return the compact-serialized JWT string
     */
    public String generateToken(UserDetails userDetails, Long userId, String dpopThumbprint) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMs);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("roles", roles)
                .claim("userId", userId)
                .claim("dpop_jkt", dpopThumbprint)
                .issuer(issuer)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(signingKey, Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Validates and parses a JWT token.
     *
     * @param token the compact-serialized JWT string
     * @return the parsed claims if the token is valid
     * @throws JwtException if the token is invalid, expired, or tampered with
     */
    public Claims validateAndGetClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extracts the username (subject) from a JWT token.
     *
     * @param token the compact-serialized JWT string
     * @return the username
     */
    public String getUsernameFromToken(String token) {
        return validateAndGetClaims(token).getSubject();
    }

    /**
     * Extracts the DPoP JWK thumbprint from a JWT token.
     *
     * @param token the compact-serialized JWT string
     * @return the DPoP JWK thumbprint, or null if not present
     */
    public String getDpopThumbprintFromToken(String token) {
        return validateAndGetClaims(token).get("dpop_jkt", String.class);
    }

    /**
     * Extracts the user ID from a JWT token.
     *
     * @param token the compact-serialized JWT string
     * @return the user ID
     */
    public Long getUserIdFromToken(String token) {
        return validateAndGetClaims(token).get("userId", Long.class);
    }

    /**
     * Extracts the roles from a JWT token.
     *
     * @param token the compact-serialized JWT string
     * @return list of role names
     */
    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        return validateAndGetClaims(token).get("roles", List.class);
    }

    /**
     * Checks whether a JWT token is valid (not expired, properly signed, correct issuer).
     *
     * @param token the compact-serialized JWT string
     * @return true if valid, false otherwise
     */
    public boolean isTokenValid(String token) {
        try {
            validateAndGetClaims(token);
            return true;
        } catch (ExpiredJwtException ex) {
            logger.warn("JWT token expired: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            logger.warn("JWT token malformed: {}", ex.getMessage());
        } catch (JwtException ex) {
            logger.warn("JWT token invalid: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            logger.warn("JWT token argument error: {}", ex.getMessage());
        }
        return false;
    }
}
