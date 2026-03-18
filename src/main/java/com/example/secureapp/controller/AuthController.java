package com.example.secureapp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.secureapp.dpop.DPoPConstants;
import com.example.secureapp.dpop.DPoPSessionBindingService;
import com.example.secureapp.dpop.DPoPValidationException;
import com.example.secureapp.dto.ApiResponse;
import com.example.secureapp.dto.LoginRequest;
import com.example.secureapp.dto.LoginResponse;
import com.example.secureapp.dto.SignUpRequest;
import com.example.secureapp.dto.UserResponse;
import com.example.secureapp.filter.JwtAuthenticationFilter;
import com.example.secureapp.security.JwtTokenService;
import com.example.secureapp.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    /** Cookie name for the JWT access token. */
    public static final String JWT_COOKIE_NAME = "ACCESS_TOKEN";

    private final AuthService authService;
    private final DPoPSessionBindingService dpopBindingService;
    private final UserDetailsService userDetailsService;
    private final JwtTokenService jwtTokenService;
    private final long jwtExpirationMs;

    public AuthController(AuthService authService,
                          DPoPSessionBindingService dpopBindingService,
                          UserDetailsService userDetailsService,
                          JwtTokenService jwtTokenService,
                          @Value("${app.security.jwt.expiration-ms}") long jwtExpirationMs) {
        this.authService = authService;
        this.dpopBindingService = dpopBindingService;
        this.userDetailsService = userDetailsService;
        this.jwtTokenService = jwtTokenService;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    /**
     * Register a new user.
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponse>> register(@Valid @RequestBody SignUpRequest signUpRequest) {
        UserResponse userResponse = authService.register(signUpRequest);
        ApiResponse<UserResponse> response = ApiResponse.success(
            "User registered successfully",
            userResponse,
            HttpStatus.CREATED.value()
        );
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Authenticates the user and sets a JWT access token in an HttpOnly cookie
     * with DPoP key binding.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request,
            HttpServletResponse httpResponse) {

        // ── DPoP: Extract proof from header ─────────────────────────────────
        String dpopProof = request.getHeader(DPoPConstants.DPOP_HEADER);
        if (dpopProof == null || dpopProof.isBlank()) {
            logger.warn("Login request missing DPoP proof header");
            return new ResponseEntity<>(
                    ApiResponse.error("Missing DPoP proof header", HttpStatus.BAD_REQUEST.value()),
                    HttpStatus.BAD_REQUEST);
        }

        // ── Authenticate user ───────────────────────────────────────────────
        UserResponse userResponse = authService.login(loginRequest);

        // ── DPoP: Validate proof and get JWK thumbprint ─────────────────────
        String dpopThumbprint;
        try {
            String requestUri = request.getRequestURL().toString();
            dpopThumbprint = dpopBindingService.validateAndGetThumbprint(
                    dpopProof, request.getMethod(), requestUri);
            logger.info("DPoP proof validated for user [{}]. Thumbprint: {}",
                    userResponse.getUsername(), dpopThumbprint);
        } catch (DPoPValidationException ex) {
            logger.warn("DPoP proof validation failed during login: {}", ex.getMessage());
            return new ResponseEntity<>(
                    ApiResponse.error("DPoP proof validation failed: " + ex.getMessage(),
                            HttpStatus.UNAUTHORIZED.value()),
                    HttpStatus.UNAUTHORIZED);
        }

        // ── Generate JWT access token with DPoP binding ─────────────────────
        UserDetails userDetails = userDetailsService.loadUserByUsername(userResponse.getUsername());
        String accessToken = jwtTokenService.generateToken(userDetails, userResponse.getId(), dpopThumbprint);

        logger.info("JWT token generated for user [{}]", userResponse.getUsername());

        // ── Set JWT in HttpOnly cookie ──────────────────────────────────────
        ResponseCookie jwtCookie = ResponseCookie.from(JWT_COOKIE_NAME, accessToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(jwtExpirationMs / 1000)
                .build();
        httpResponse.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());

        LoginResponse loginResponse = LoginResponse.builder()
                .expiresIn(jwtExpirationMs)
                .user(userResponse)
                .build();

        ApiResponse<LoginResponse> response = ApiResponse.success(
            "Login successful",
            loginResponse,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Logout endpoint. Clears the JWT HttpOnly cookie.
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<?>> logout(HttpServletResponse httpResponse) {
        ResponseCookie clearCookie = ResponseCookie.from(JWT_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(0)
                .build();
        httpResponse.addHeader(HttpHeaders.SET_COOKIE, clearCookie.toString());

        ApiResponse<?> response = ApiResponse.success(
            "Logout successful",
            null,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Get the currently authenticated user's profile.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(HttpServletRequest request) {
        Long userId = (Long) request.getAttribute(JwtAuthenticationFilter.REQUEST_ATTR_USER_ID);
        if (userId == null) {
            return new ResponseEntity<>(
                ApiResponse.error("User not authenticated", HttpStatus.UNAUTHORIZED.value()),
                HttpStatus.UNAUTHORIZED
            );
        }

        UserResponse userResponse = authService.getUserById(userId);
        ApiResponse<UserResponse> response = ApiResponse.success(
            "User fetched successfully",
            userResponse,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}