# SecureApp - Production-Grade Spring Boot Backend

A enterprise-level Spring Boot 4.0.3 application with comprehensive security features, session management, and role-based access control.

## Project Overview

**SecureApp** is a production-ready backend application built with Spring Boot, featuring:

- **Authentication & Authorization**: Session-based authentication with server-side sessions stored in PostgreSQL (JDBC)
- **Security Hardening**: CSRF protection, secure headers, CORS configuration for Angular frontends
- **Database**: PostgreSQL integration with JPA/Hibernate ORM
- **Session Management**: Spring Session JDBC for database-backed distributed session handling
- **Input Validation**: Jakarta Bean Validation with comprehensive error handling
- **API Standards**: RESTful APIs with standardized response format
- **Role-Based Access Control**: Fine-grained authorization using Spring Security

## Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Runtime** | Java | 21 |
| **Framework** | Spring Boot | 4.0.3 |
| **Security** | Spring Security | Latest |
| **Database** | PostgreSQL | 42.7.3 |
| **Session Store** | Spring Session JDBC | Latest |
| **ORM** | Spring Data JPA/Hibernate | Latest |
| **Validation** | Jakarta Bean Validation | Latest |
| **Build Tool** | Maven | 3.9.12+ |
| **Annotations** | Lombok | Latest |

## Project Structure

```
SecureDemo/
├── pom.xml                                    # Maven configuration
├── init-database.sql                          # Database schema + seed data
├── SecureApp-API.postman_collection.json      # Postman API collection
└── src/main/
    ├── java/com/example/secureapp/
    │   ├── SecureAppApplication.java         # Main Spring Boot class
    │   ├── config/
    │   │   ├── SecurityConfig.java            # Security & CORS configuration
    │   │   ├── SessionConfig.java             # JDBC session store configuration
    │   │   └── WebMvcConfig.java              # MVC interceptor registration
    │   ├── controller/
    │   │   ├── AuthController.java            # Authentication endpoints
    │   │   └── DashboardController.java       # Protected endpoints
    │   ├── service/
    │   │   └── AuthService.java               # Authentication business logic
    │   ├── repository/
    │   │   ├── UserRepository.java            # User data access
    │   │   └── RoleRepository.java            # Role data access
    │   ├── entity/
    │   │   ├── User.java                      # User JPA entity
    │   │   └── Role.java                      # Role JPA entity
    │   ├── dto/
    │   │   ├── LoginRequest.java              # Login DTO
    │   │   ├── SignUpRequest.java             # Registration DTO
    │   │   ├── UserResponse.java              # User response DTO
    │   │   └── ApiResponse.java               # Generic API response wrapper
    │   ├── security/
    │   │   ├── CustomUserDetailsService.java  # Spring Security user details service
    │   │   ├── AuthorizationInterceptor.java  # Custom authorization interceptor
    │   │   └── RolePermissionMapping.java     # Centralized role-path permission map
    │   ├── exception/
    │   │   ├── ResourceNotFoundException.java # 404 exception
    │   │   ├── BadRequestException.java       # 400 exception
    │   │   └── GlobalExceptionHandler.java    # Global exception handler
    │   ├── filter/
    │   │   ├── SecurityHeadersFilter.java     # Adds 8 security headers
    │   │   └── SessionValidationFilter.java   # Validates session before controllers
    │   └── util/
    │       ├── SecurityUtil.java              # Request-level security utilities
    │       └── SecurityUtils.java             # Static security context utilities
    └── resources/
        └── application.properties              # Configuration file
```

## Security Features

### 1. **Session Management**
- Server-side sessions stored in PostgreSQL via JDBC (Spring Session JDBC)
- HttpOnly cookies (cannot be accessed via JavaScript)
- Secure flag (HTTPS only in production)
- SameSite=Strict policy (CSRF protection)
- Session timeout: 15 minutes (900 seconds)
- Max sessions per user: 1
- Custom SessionValidationFilter for defense-in-depth session checks

### 2. **Authentication**
- Username/password-based login
- Bcrypt password hashing (strength 12)
- Login endpoint: `POST /api/auth/login`
- Registration endpoint: `POST /api/auth/register`
- Logout endpoint: `POST /api/auth/logout`
- Session attribute storage for user context

### 3. **Authorization**
- Role-based access control (RBAC)
- Default roles: `ROLE_USER`, `ROLE_ADMIN`, `ROLE_MODERATOR`
- Protected endpoints require authentication
- Admin endpoints require `ROLE_ADMIN`
- Method-level security with `@PreAuthorize`
- Custom `AuthorizationInterceptor` with centralized `RolePermissionMapping`

### 4. **CSRF Protection**
- Built-in Spring Security CSRF protection
- Token validation on state-changing requests
- Works seamlessly with session-based authentication

### 5. **Security Headers**
- `Content-Security-Policy`: Restricts resource loading
- `X-XSS-Protection`: XSS attack prevention
- `X-Frame-Options`: Clickjacking protection (DENY)
- `X-Content-Type-Options`: Prevents MIME-sniffing (nosniff)
- `Strict-Transport-Security`: Enforces HTTPS (1 year with preload)
- `Referrer-Policy`: Controls referrer information
- `Permissions-Policy`: Disables camera, microphone, geolocation, etc.
- `Cache-Control`: Prevents caching of sensitive data

### 6. **CORS Configuration**
- Configured for Angular frontend (localhost:4200)
- Supports credentials (cookies)
- Allowed methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
- Max age: 1 hour

### 7. **Input Validation**
- Jakarta Bean Validation annotations
- Comprehensive error messages
- Global exception handling with validation error details

## API Endpoints

### Authentication Endpoints

#### Register New User
```
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}

Response (201 Created):
{
  "success": true,
  "message": "User registered successfully",
  "statusCode": 201,
  "data": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "enabled": true,
    "roles": ["ROLE_USER"],
    "createdAt": "2026-03-10T12:00:00"
  }
}
```

#### Login
```
POST /api/auth/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "SecurePass123!"
}

Response (200 OK):
Sets JSESSIONID cookie with HttpOnly flag
{
  "success": true,
  "message": "Login successful",
  "statusCode": 200,
  "data": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "roles": ["ROLE_USER"],
    "lastLogin": "2026-03-10T12:05:00"
  }
}
```

#### Get Current User
```
GET /api/auth/me
Cookie: JSESSIONID=xxx

Response (200 OK):
{
  "success": true,
  "message": "User fetched successfully",
  "statusCode": 200,
  "data": { ... }
}
```

#### Logout
```
POST /api/auth/logout
Cookie: JSESSIONID=xxx

Response (200 OK):
Invalidates JSESSIONID cookie
{
  "success": true,
  "message": "Logout successful",
  "statusCode": 200
}
```

### Protected Endpoints

#### Dashboard (Authenticated Users)
```
GET /api/dashboard
Cookie: JSESSIONID=xxx

Response (200 OK):
{
  "success": true,
  "message": "Dashboard data fetched",
  "statusCode": 200,
  "data": {
    "message": "Welcome to dashboard, john_doe"
  }
}
```

#### Admin Users List (ROLE_ADMIN Only)
```
GET /api/admin/users
Cookie: JSESSIONID=xxx (Admin user)

Response (200 OK):
{
  "success": true,
  "message": "Users data fetched",
  "statusCode": 200
}
```

### Health Check
```
GET /api/health

Response (200 OK):
{
  "success": true,
  "message": "Service is healthy",
  "statusCode": 200,
  "data": {
    "status": "UP"
  }
}
```

## Setup & Installation

### Prerequisites
- Java 21 (JDK)
- Maven 3.9.12+
- PostgreSQL 12+

### Step 1: Database Setup
```sql
-- Create database
CREATE DATABASE secureapp_db;

-- Connect to database
\c secureapp_db;

-- Create roles table
CREATE TABLE roles (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  description VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create users table
CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password TEXT NOT NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  phone_number VARCHAR(20),
  address TEXT,
  enabled BOOLEAN DEFAULT true,
  account_non_expired BOOLEAN DEFAULT true,
  account_non_locked BOOLEAN DEFAULT true,
  credentials_non_expired BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
);

-- Create user_roles junction table
CREATE TABLE user_roles (
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES 
('ROLE_USER', 'Standard user role'),
('ROLE_ADMIN', 'Administrator role'),
('ROLE_MODERATOR', 'Moderator role');

-- Create indexes
CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_email ON users(email);

-- Note: init-database.sql also creates Spring Session JDBC tables
-- (SPRING_SESSION, SPRING_SESSION_ATTRIBUTES) required for session storage
```

### Step 2: Configure Application Properties
Edit `src/main/resources/application.properties`:
```properties
# PostgreSQL
spring.datasource.url=jdbc:postgresql://localhost:5432/secureapp_db
spring.datasource.username=postgres
spring.datasource.password=your_password
```

### Step 3: Build the Project
```bash
cd E:\Projects\Agristack\poc\SecureDemo
mvn clean compile
mvn package
```

### Step 4: Run the Application
```bash
java -jar target/secureapp-1.0.0.jar
```

Application will start on: `http://localhost:8080/api`

## Configuration Reference

### application.properties

| Property | Description | Default |
|----------|-------------|---------|
| `server.port` | Server port | 8080 |
| `server.servlet.context-path` | Context path | /api |
| `spring.datasource.url` | PostgreSQL URL | jdbc:postgresql://localhost:5432/secureapp_db |
| `spring.jpa.hibernate.ddl-auto` | Hibernate DDL strategy | update |
| `spring.session.store-type` | Session store | jdbc |
| `server.servlet.session.cookie.max-age` | Session max age | 900 (15 minutes) |
| `server.servlet.session.timeout` | Session timeout | 15m |

## Building from Source

### Prerequisites Verification
```bash
java -version
mvn --version
```

### Maven Build Process
```bash
# Clean and compile
mvn clean compile

# Run tests (if configured)
mvn test

# Package JAR
mvn package

# Build with all phases
mvn clean package
```

### Build Output
- Compiled classes: `target/classes/`
- JAR file: `target/secureapp-1.0.0.jar`

## Production Deployment

### Pre-Deployment Checklist
- [ ] Update `application.properties` with production URLs
- [ ] Configure HTTPS certificate
- [ ] Set secure database passwords via environment variables
- [ ] Enable Spring Security HTTPS only
- [ ] Configure proper CORS origins
- [ ] Set up database backups
- [ ] Configure logging to files
- [ ] Set environment variables for sensitive data

### Docker Deployment
Create a `Dockerfile`:
```dockerfile
FROM openjdk:21-jdk-slim
COPY target/secureapp-1.0.0.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

Build and run:
```bash
docker build -t secureapp:1.0.0 .
docker run -p 8080:8080 --env-file .env secureapp:1.0.0
```

## Troubleshooting

### Common Issues

**1. Database Connection Error**
```
Solution: Verify PostgreSQL is running and credentials in application.properties
psql -U postgres -h localhost -d secureapp_db
```

**2. Port Already in Use**
```
Solution: Change server.port in application.properties or:
netstat -ano | findstr :8080
taskkill /PID <PID> /F
```

**3. Maven Build Failures**
```
Solution: Clear Maven cache and rebuild
mvn clean -U install
```

## Security Best Practices

1. **Passwords**: Use strong passwords (min 8 chars, mix of uppercase, lowercase, numbers, special chars)
2. **HTTPS**: Always use HTTPS in production (set `server.ssl.enabled=true`)
3. **Session**: Set appropriate timeout based on security requirements
4. **CORS**: Restrict CORS origins to trusted domains only
5. **Secrets**: Never commit passwords/API keys - use environment variables
6. **Logging**: Don't log sensitive data (passwords, tokens, PII)
7. **Database**: Use parameterized queries (JPA handles this automatically)
8. **Updates**: Keep Spring Boot and dependencies updated

## Testing the API

### Using cURL
```bash
# Register
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "password": "TestPass123!",
    "confirmPassword": "TestPass123!"
  }'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "username": "testuser",
    "password": "TestPass123!"
  }'

# Access Protected Endpoint
curl -X GET http://localhost:8080/api/dashboard \
  -b cookies.txt

# Logout
curl -X POST http://localhost:8080/api/auth/logout \
  -b cookies.txt
```

### Using Postman
1. Import the provided Postman collection (if available)
2. Set environment variables for base URL
3. Login first to get session cookie
4. Use session cookie for protected endpoints

## Development

### Adding New Endpoints
1. Create controller in `controller/` package
2. Add service logic in `service/` package
3. Use `@PreAuthorize` for role-based security
4. Add validation DTOs in `dto/` package
5. Use `ApiResponse<T>` for consistent response format

### Adding New Entities
1. Create entity in `entity/` package with JPA annotations
2. Create repository in `repository/` package extending `JpaRepository`
3. Use `@Table`, `@Column` for database mapping
4. Add validation constraints from `jakarta.validation`

### Exception Handling
All exceptions should extend `RuntimeException` or custom exception classes. Global exception handler will return:
```json
{
  "success": false,
  "message": "Error description",
  "statusCode": 400,
  "timestamp": 1678425600000
}
```

## Performance Optimization

- **Caching**: Configure Spring Cache with a suitable provider
- **Database**: Add indexes on frequently queried columns
- **Connection Pooling**: HikariCP (auto-configured)
- **Lazy Loading**: Use `FetchType.LAZY` for relationships
- **Pagination**: Implement for large result sets

## License

Proprietary - Enterprise Application

## Support

For issues and support, contact the development team.

---

**Created**: March 10, 2026
**Version**: 1.0.0
**Status**: Production Ready
