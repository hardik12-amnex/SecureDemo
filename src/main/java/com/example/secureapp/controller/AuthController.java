package com.example.secureapp.controller;

import com.example.secureapp.dto.ApiResponse;
import com.example.secureapp.dto.LoginRequest;
import com.example.secureapp.dto.SignUpRequest;
import com.example.secureapp.dto.UserResponse;
import com.example.secureapp.service.AuthService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

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

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<UserResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpSession session) {
        UserResponse userResponse = authService.login(loginRequest);
        
        // Store user info in session
        session.setAttribute("userId", userResponse.getId());
        session.setAttribute("username", userResponse.getUsername());
        session.setAttribute("roles", userResponse.getRoles());
        
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
