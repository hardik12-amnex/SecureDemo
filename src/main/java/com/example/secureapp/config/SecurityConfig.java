package com.example.secureapp.config;

import java.util.Arrays;

import com.example.secureapp.dpop.DPoPAuthenticationFilter;
import com.example.secureapp.filter.SessionValidationFilter;
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

    private final SessionValidationFilter sessionValidationFilter;
    private final DPoPAuthenticationFilter dpopAuthenticationFilter;

    public SecurityConfig(SessionValidationFilter sessionValidationFilter,
                          DPoPAuthenticationFilter dpopAuthenticationFilter) {
        this.sessionValidationFilter = sessionValidationFilter;
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
        // Allow all headers (includes DPoP custom header)
        configuration.setAllowedHeaders(Arrays.asList("*"));
        // Expose headers for client-side access (DPoP included for proof-of-possession flow)
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type", "DPoP"));
        // Enable credentials (cookies, HTTP authentication, etc.)
        configuration.setAllowCredentials(true);
        // Set max age for preflight cache
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Configure the security filter chain with session-based authentication,
     * CSRF protection, security headers, and authorization rules
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS with the custom configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Enable CSRF protection using CookieCsrfTokenRepository
            .csrf(csrf -> csrf
            		.ignoringRequestMatchers(
                            "/auth/login",
                            "/auth/register",
                            "/auth/logout",
                            "/health"
                        )
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            
            // Configure session management for session-based authentication
            .sessionManagement(session -> session
                // Create session only when required (don't create unnecessarily)
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                // Session Fixation Protection: after authentication, the existing
                // session ID is changed (Servlet 3.1+ changeSessionId) so that an
                // attacker who knew the pre-login session ID can no longer hijack it.
                // Flow: oldSessionId → invalidated, newSessionId → generated
                .sessionFixation(fix -> fix.changeSessionId())
                // Limit to 1 concurrent session per user
                .maximumSessions(1)
                // Don't prevent login, allow new login to replace old session
                .maxSessionsPreventsLogin(false)
            )
            
            // Configure session cookie settings
            .servletApi(servlet -> servlet
                .rolePrefix("ROLE_")
            )
            
            // Register DPoPAuthenticationFilter before UsernamePasswordAuthenticationFilter
            // This ensures DPoP proof-of-possession is verified early in the filter chain
            .addFilterBefore(dpopAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            
            // Register SessionValidationFilter after DPoP filter but still before UsernamePasswordAuthenticationFilter
            // This ensures session validity is checked after DPoP verification
            .addFilterAfter(sessionValidationFilter, DPoPAuthenticationFilter.class)
            
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
            
            // Configure logout
            .logout(logout -> logout
                .logoutUrl("/auth/logout")
                .logoutSuccessUrl("/auth/login")
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .permitAll()
            );

        return http.build();
    }
}
