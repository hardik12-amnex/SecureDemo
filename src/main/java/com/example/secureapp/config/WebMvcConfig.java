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
 * <p>Request flow (stateless):
 * Browser → Spring Security Filter Chain → JwtAuthenticationFilter
 * → DPoPAuthenticationFilter → <b>AuthorizationInterceptor (registered here)</b> → Controller
 */
@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthorizationInterceptor authorizationInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authorizationInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(
                        "/auth/login",
                        "/auth/register",
                        "/auth/logout",
                        "/health",
                        "/error"
                );
    }
}