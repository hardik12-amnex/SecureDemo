package com.example.secureapp.config;

import com.example.secureapp.security.AuthorizationInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC configuration that registers the {@link AuthorizationInterceptor}
 * into the Spring MVC interceptor chain.
 *
 * <p>Request flow:
 * Browser → NGINX → Spring Security Filter Chain → SessionValidationFilter
 * → <b>AuthorizationInterceptor (registered here)</b> → Controller
 *
 * <p>Excluded paths (public endpoints) are not intercepted:
 * <ul>
 *   <li>/auth/login</li>
 *   <li>/auth/register</li>
 *   <li>/auth/logout</li>
 *   <li>/health</li>
 * </ul>
 */
@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthorizationInterceptor authorizationInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authorizationInterceptor)
                // Intercept all paths
                .addPathPatterns("/**")
                // Exclude public endpoints from authorization interception
                .excludePathPatterns(
                        "/auth/login",
                        "/auth/register",
                        "/auth/logout",
                        "/health",
                        "/error"
                );
    }
}
