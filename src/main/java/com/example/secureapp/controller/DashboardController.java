package com.example.secureapp.controller;

import com.example.secureapp.dto.ApiResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class DashboardController {

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<?>> health() {
        Map<String, Object> data = new HashMap<>();
        data.put("status", "UP");
        data.put("timestamp", System.currentTimeMillis());
        
        ApiResponse<?> response = ApiResponse.success(
            "Service is healthy",
            data,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/dashboard")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<?>> dashboard(HttpSession session) {
        String username = (String) session.getAttribute("username");
        
        Map<String, Object> data = new HashMap<>();
        data.put("message", "Welcome to dashboard, " + username);
        data.put("timestamp", System.currentTimeMillis());
        
        ApiResponse<?> response = ApiResponse.success(
            "Dashboard data fetched",
            data,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<?>> getUsers() {
        Map<String, Object> data = new HashMap<>();
        data.put("message", "All users (Admin only)");
        data.put("timestamp", System.currentTimeMillis());
        
        ApiResponse<?> response = ApiResponse.success(
            "Users data fetched",
            data,
            HttpStatus.OK.value()
        );
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
