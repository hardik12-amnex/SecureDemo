-- =============================================================================
-- SecureApp Database Initialization Script
-- =============================================================================
-- Purpose: Initialize PostgreSQL database schema and seed initial data
-- Created: March 10, 2026
-- =============================================================================

-- Create database (run as superuser)
-- CREATE DATABASE secureapp_db;
-- \c secureapp_db;

-- =============================================================================
-- ROLES TABLE
-- =============================================================================
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS roles CASCADE;

CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_role_name ON roles(name);

-- =============================================================================
-- USERS TABLE
-- =============================================================================
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20),
    address TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    account_non_expired BOOLEAN NOT NULL DEFAULT true,
    account_non_locked BOOLEAN NOT NULL DEFAULT true,
    credentials_non_expired BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_email ON users(email);
CREATE INDEX idx_enabled ON users(enabled);

-- =============================================================================
-- USER_ROLES JUNCTION TABLE
-- =============================================================================
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- =============================================================================
-- NOTE: SPRING_SESSION tables are NO LONGER required.
-- =============================================================================
-- The application now uses stateless JWT-based authentication.
-- Authentication state is carried in the JWT access token (Authorization header),
-- not in server-side sessions. No session tables are needed.
--
-- If upgrading from the session-based version, you can safely drop the old tables:
--   DROP TABLE IF EXISTS SPRING_SESSION_ATTRIBUTES;
--   DROP TABLE IF EXISTS SPRING_SESSION;
-- =============================================================================

-- =============================================================================
-- INITIAL DATA
-- =============================================================================

-- Insert default roles
INSERT INTO roles (name, description, created_at, updated_at) VALUES 
    ('ROLE_USER', 'Standard user role with basic permissions', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('ROLE_ADMIN', 'Administrator role with full permissions', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('ROLE_MODERATOR', 'Moderator role with content management permissions', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Sample admin user (password: AdminPass123! - bcrypt encoded with strength 12)
-- Note: In production, create admin users with a secure random password
INSERT INTO users (
    username, email, password, first_name, last_name, phone_number, address,
    enabled, account_non_expired, account_non_locked, credentials_non_expired,
    created_at, updated_at
) VALUES (
    'admin',
    'admin@secureapp.com',
    '$2a$12$InTASUix5RZlCSPz4yRZjOqyRqEQ8P0uWIp2aRmQ7oN9S4iSckm7u',
    'System',
    'Administrator',
    '+1-800-ADMIN-01',
    '123 Admin Street, Tech City, TC 12345',
    true,
    true,
    true,
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Sample regular user (password: UserPass123! - bcrypt encoded with strength 12)
INSERT INTO users (
    username, email, password, first_name, last_name, phone_number, address,
    enabled, account_non_expired, account_non_locked, credentials_non_expired,
    created_at, updated_at
) VALUES (
    'testuser',
    'test@example.com',
    '$2a$12$BwebEBrJrel8AKxPmMd5IO7ZfXJV.P/z3wZTIuRB/i.8nSscGhAP.',
    'Test',
    'User',
    '+1-800-TEST-01',
    '456 Test Avenue, Demo City, DC 54321',
    true,
    true,
    true,
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Assign roles to users
-- Admin gets both ADMIN and USER roles
INSERT INTO user_roles (user_id, role_id) 
SELECT u.id, r.id FROM users u, roles r 
WHERE u.username = 'admin' AND r.name = 'ROLE_ADMIN';

INSERT INTO user_roles (user_id, role_id) 
SELECT u.id, r.id FROM users u, roles r 
WHERE u.username = 'admin' AND r.name = 'ROLE_USER';

-- Test user gets USER role
INSERT INTO user_roles (user_id, role_id) 
SELECT u.id, r.id FROM users u, roles r 
WHERE u.username = 'testuser' AND r.name = 'ROLE_USER';

-- =============================================================================
-- VERIFICATION QUERIES
-- =============================================================================

-- View all roles
SELECT * FROM roles;

-- View all users
SELECT id, username, email, first_name, last_name, enabled, created_at FROM users;

-- View user-role assignments
SELECT u.username, r.name FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
ORDER BY u.username, r.name;

-- =============================================================================
-- NOTES
-- =============================================================================
/*
Default Test Credentials:
1. Admin User:
   - Username: admin
   - Password: AdminPass123!
   - Roles: ROLE_ADMIN, ROLE_USER

2. Regular User:
   - Username: testuser
   - Password: UserPass123!
   - Roles: ROLE_USER

IMPORTANT: Change these passwords after first login in production!

Password Encoding:
All passwords are BCrypt encoded with strength 12.
To generate new passwords, use the Spring Security PasswordEncoder:
- Use AuthService.register() endpoint for new user registration
- Passwords are automatically hashed on registration
*/