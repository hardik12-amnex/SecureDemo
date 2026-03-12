package com.example.secureapp.controller;

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
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

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
     * Authenticates the user and performs <b>session rotation</b> (session fixation protection).
     *
     * <p><b>Session Fixation Attack scenario prevented:</b>
     * <ol>
     *   <li>Attacker creates a session and obtains the session ID</li>
     *   <li>Attacker sends victim a link containing that session ID</li>
     *   <li>Victim logs in — without rotation the session ID stays the same</li>
     *   <li>Attacker already knows the session ID → hijacks the account</li>
     * </ol>
     *
     * <p><b>Protection applied here:</b>
     * <ol>
     *   <li>Old session (if any) is invalidated</li>
     *   <li>A brand-new session with a new ID is created</li>
     *   <li>User attributes are stored only in the new session</li>
     * </ol>
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<UserResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {
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
