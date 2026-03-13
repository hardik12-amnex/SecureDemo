package com.example.secureapp.controller;

import com.example.secureapp.dpop.DPoPConstants;
import com.example.secureapp.dpop.DPoPSessionBindingService;
import com.example.secureapp.dpop.DPoPValidationException;
import com.example.secureapp.dto.ApiResponse;
import com.example.secureapp.dto.LoginRequest;
import com.example.secureapp.dto.SignUpRequest;
import com.example.secureapp.dto.UserResponse;
import com.example.secureapp.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final DPoPSessionBindingService dpopSessionBindingService;
    private final UserDetailsService userDetailsService;

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
     * Authenticates the user, performs session rotation, and binds the client's DPoP public key.
     *
     * <h3>Why is a DPoP header required at login when the user has no session yet?</h3>
     * <p>The DPoP proof is <b>NOT</b> an auth token — it is a <b>self-signed JWT</b> that
     * the client creates entirely on its own using the browser's WebCrypto API.
     * No session, no token, and no server interaction is needed to produce it.</p>
     *
     * <p><b>Client-side flow before login:</b></p>
     * <ol>
     *   <li>Angular app loads in the browser</li>
     *   <li>Client generates an ECDSA P-256 keypair locally (WebCrypto: {@code crypto.subtle.generateKey})</li>
     *   <li>Client builds a JWT with the <b>public key in the header</b></li>
     *   <li>Client signs the JWT with the <b>private key</b> (proof of possession)</li>
     *   <li>Client sends: {@code POST /auth/login} with {@code Body: {username, password}}
     *       and {@code DPoP: <self-signed-jwt>}</li>
     * </ol>
     *
     * <p>The server then validates the proof, extracts the public key, and binds it
     * to the newly-created session. All subsequent requests must include a fresh DPoP
     * proof signed by the same private key — this is verified by
     * {@link com.example.secureapp.dpop.DPoPAuthenticationFilter}.</p>
     *
     * <h3>Session Fixation Protection</h3>
     * <ol>
     *   <li>Old session (if any) is invalidated</li>
     *   <li>A brand-new session with a new ID is created</li>
     *   <li>User attributes and DPoP public key are stored only in the new session</li>
     * </ol>
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<UserResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {

        // ── DPoP: Extract proof from header ─────────────────────────────────
        String dpopProof = request.getHeader(DPoPConstants.DPOP_HEADER);
        if (dpopProof == null || dpopProof.isBlank()) {
            logger.warn("Login request missing DPoP proof header");
            return new ResponseEntity<>(
                    ApiResponse.error("Missing DPoP proof header", HttpStatus.BAD_REQUEST.value()),
                    HttpStatus.BAD_REQUEST);
        }

        UserResponse userResponse = authService.login(loginRequest);

        // ── Session Rotation (Session Fixation Protection) ──────────────────
        // Step 1: Invalidate any existing session to discard attacker-planted session IDs
        HttpSession oldSession = request.getSession(false);
        String oldSessionId = (oldSession != null) ? oldSession.getId() : "none";
        if (oldSession != null) {
            oldSession.invalidate();
        }

        // Step 2: Create a brand-new session with a fresh ID
        HttpSession newSession = request.getSession(true);
        logger.info("Session rotated on login for user [{}]: oldSessionId={}, newSessionId={}",
                userResponse.getUsername(), oldSessionId, newSession.getId());

        // Step 3: Store user info in the new session
        newSession.setAttribute("userId", userResponse.getId());
        newSession.setAttribute("username", userResponse.getUsername());
        newSession.setAttribute("roles", userResponse.getRoles());

        // Step 4: Set Authentication in SecurityContext so Spring Security
        // recognizes the user on subsequent requests
        UserDetails userDetails = userDetailsService.loadUserByUsername(userResponse.getUsername());
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        // Persist SecurityContext in the session so it is restored on future requests
        newSession.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

        // ── DPoP: Bind client public key to the new session ─────────────────
        try {
            String requestUri = request.getRequestURL().toString();
            dpopSessionBindingService.validateAndBindKey(dpopProof, request.getMethod(), requestUri, newSession);
            logger.info("DPoP key bound to session for user [{}]", userResponse.getUsername());
        } catch (DPoPValidationException ex) {
            logger.warn("DPoP proof validation failed during login: {}", ex.getMessage());
            newSession.invalidate();
            return new ResponseEntity<>(
                    ApiResponse.error("DPoP proof validation failed: " + ex.getMessage(),
                            HttpStatus.UNAUTHORIZED.value()),
                    HttpStatus.UNAUTHORIZED);
        }
        // ─────────────────────────────────────────────────────────────────────

        ApiResponse<UserResponse> response = ApiResponse.success(
            "Login successful",
            userResponse,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<?>> logout(HttpSession session) {
        session.invalidate();
        ApiResponse<?> response = ApiResponse.success(
            "Logout successful",
            null,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
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
