package com.example.secureapp.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class SecurityUtil {

    public String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0];
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }

    public boolean isSecureConnection(HttpServletRequest request) {
        return request.isSecure() || 
               "https".equals(request.getHeader("X-Forwarded-Proto")) ||
               "on".equals(request.getHeader("X-SSL"));
    }
}
