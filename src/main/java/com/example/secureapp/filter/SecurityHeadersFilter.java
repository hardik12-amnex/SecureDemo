package com.example.secureapp.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom filter to add additional security headers to HTTP responses.
 * This filter ensures that essential security headers are included in all responses.
 */
@Component
public class SecurityHeadersFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization code if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Content-Security-Policy header - restrict resource loading
        httpResponse.setHeader("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'");

        // X-Frame-Options header - prevent clickjacking attacks
        httpResponse.setHeader("X-Frame-Options", "DENY");

        // X-Content-Type-Options header - prevent MIME type sniffing
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");

        // Strict-Transport-Security header - enforce HTTPS
        // max-age=31536000 (1 year), includeSubDomains, preload
        httpResponse.setHeader("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains; preload");

        // X-XSS-Protection header - legacy XSS protection (for older browsers)
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");

        // Referrer-Policy header - control referrer information
        httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Permissions-Policy header (formerly Feature-Policy) - control browser features
        httpResponse.setHeader("Permissions-Policy", 
            "accelerometer=(), " +
            "camera=(), " +
            "geolocation=(), " +
            "gyroscope=(), " +
            "magnetometer=(), " +
            "microphone=(), " +
            "payment=(), " +
            "usb=()");

        // Set no-cache headers to prevent caching of sensitive data
        httpResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        httpResponse.setHeader("Pragma", "no-cache");
        httpResponse.setHeader("Expires", "0");

        chain.doFilter(request, httpResponse);
    }

    @Override
    public void destroy() {
        // Cleanup code if needed
    }
}
