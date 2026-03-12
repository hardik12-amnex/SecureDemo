package com.example.secureapp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;

/**
 * Session configuration for database-backed session storage with JDBC
 * - Sessions are stored in the database for distributed system support
 * - Session timeout is set to 15 minutes (900 seconds)
 * - Cookie settings are configured in application.properties
 */
@Configuration
@EnableJdbcHttpSession(maxInactiveIntervalInSeconds = 900) // 15 minutes
public class SessionConfig {
    // Cookie and session configuration is handled via application.properties
    // This allows for better control over deployment-specific settings
}
