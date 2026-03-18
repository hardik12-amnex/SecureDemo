package com.example.secureapp.config;

import java.util.Arrays;

import com.example.secureapp.dpop.DPoPAuthenticationFilter;
import com.example.secureapp.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final DPoPAuthenticationFilter dpopAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          DPoPAuthenticationFilter dpopAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.dpopAuthenticationFilter = dpopAuthenticationFilter;
    }

    /**
     * Configure password encoder using BCrypt with strength 12
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Configure authentication manager for user authentication
     */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Configure CORS to allow only http://localhost:4200 with credentials support
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow only localhost:4200 for CORS requests
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
        // Allow standard HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        // Allow all headers (includes DPoP and Authorization custom headers)
        configuration.setAllowedHeaders(Arrays.asList("*"));
        // Expose headers for client-side access (DPoP and Authorization included)
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type", "DPoP"));
        // Enable credentials (Authorization headers)
        configuration.setAllowCredentials(true);
        // Set max age for preflight cache
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Configure the security filter chain with stateless JWT-based authentication,
     * DPoP proof-of-possession, security headers, and authorization rules.
     *
     * <p><b>Stateless architecture with HttpOnly cookie transport:</b></p>
     * <ul>
     *   <li>No server-side sessions (SessionCreationPolicy.STATELESS)</li>
     *   <li>JWT token transported in HttpOnly, Secure, SameSite=Strict cookie</li>
     *   <li>CSRF protection enabled (CookieCsrfTokenRepository) because cookies
     *       are auto-attached by browser — CSRF token required for state-changing requests</li>
     *   <li>JWT token contains user identity, roles, and DPoP key binding</li>
     * </ul>
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS with the custom configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Enable CSRF protection — required because JWT is transported in an
            // HttpOnly cookie that the browser automatically attaches to requests.
            // Public endpoints are excluded from CSRF enforcement.
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    "/auth/login",
                    "/auth/register",
                    "/auth/logout",
                    "/health"
                )
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            
            // Stateless session management — no server-side sessions.
            // The cookie carries a self-contained JWT, NOT a session ID.
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Configure role prefix
            .servletApi(servlet -> servlet
                .rolePrefix("ROLE_")
            )
            
            // Register JwtAuthenticationFilter before UsernamePasswordAuthenticationFilter
            // This extracts and validates the JWT token and sets the SecurityContext
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            
            // Register DPoPAuthenticationFilter after JWT filter
            // This validates the DPoP proof and compares the JWK thumbprint with the JWT-bound thumbprint
            .addFilterAfter(dpopAuthenticationFilter, JwtAuthenticationFilter.class)
            
            // Configure authorization rules
            .authorizeHttpRequests(authz -> authz
                // Public endpoints - allow without authentication
                // Note: context-path /api is stripped, so use servlet-relative paths
                .requestMatchers("/auth/login", "/auth/register", "/auth/logout").permitAll()
                .requestMatchers("/health", "/actuator/health").permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            
            // Add security headers
            .headers(headers -> headers
                // Content Security Policy header
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; " +
                        "script-src 'self'; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        "font-src 'self'; " +
                        "connect-src 'self'")
                )
                // X-Frame-Options header to prevent clickjacking
                .frameOptions(frame -> frame.deny())
            )
            
            // Disable default logout (handled manually in AuthController)
            .logout(logout -> logout.disable());

        return http.build();
    }
}