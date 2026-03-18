package com.example.secureapp.service;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.secureapp.dto.LoginRequest;
import com.example.secureapp.dto.SignUpRequest;
import com.example.secureapp.dto.UserResponse;
import com.example.secureapp.entity.Role;
import com.example.secureapp.entity.User;
import com.example.secureapp.exception.BadRequestException;
import com.example.secureapp.exception.ResourceNotFoundException;
import com.example.secureapp.repository.RoleRepository;
import com.example.secureapp.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponse register(SignUpRequest signUpRequest) {
        // Validate that passwords match
        if (!signUpRequest.getPassword().equals(signUpRequest.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        // Check if user already exists
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            throw new BadRequestException("Username already taken");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new BadRequestException("Email already registered");
        }

        // Create new user
        User user = User.builder()
            .username(signUpRequest.getUsername())
            .email(signUpRequest.getEmail())
            .firstName(signUpRequest.getFirstName())
            .lastName(signUpRequest.getLastName())
            .password(passwordEncoder.encode(signUpRequest.getPassword()))
            .enabled(true)
            .accountNonExpired(true)
            .accountNonLocked(true)
            .credentialsNonExpired(true)
            .build();

        // Assign default USER role
        Role userRole = roleRepository.findByName("ROLE_USER")
            .orElseThrow(() -> new ResourceNotFoundException("Default role not found"));
        
        user.getRoles().add(userRole);
        User savedUser = userRepository.save(user);

        return convertToUserResponse(savedUser);
    }

    @Transactional
    public UserResponse login(LoginRequest loginRequest) {
        // Use generic error message for both "user not found" and "wrong password"
        // to prevent account enumeration attacks
        User user = userRepository.findByUsername(loginRequest.getUsername())
            .orElseThrow(() -> new BadRequestException("Invalid credentials"));

        logger.debug("Login attempt for user [{}]", loginRequest.getUsername());

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            logger.warn("Password mismatch for user [{}]", loginRequest.getUsername());
            throw new BadRequestException("Invalid credentials");
        }

        if (!user.getEnabled()) {
            // Generic message — do not reveal account status
            throw new BadRequestException("Invalid credentials");
        }

        if (!user.getAccountNonLocked()) {
            // Generic message — do not reveal lock status
            throw new BadRequestException("Invalid credentials");
        }

        // Update last login time
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        return convertToUserResponse(user);
    }

    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
        return convertToUserResponse(user);
    }

    public UserResponse getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
        return convertToUserResponse(user);
    }

    private UserResponse convertToUserResponse(User user) {
        Set<String> roleNames = user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.toSet());

        return UserResponse.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .firstName(user.getFirstName())
            .lastName(user.getLastName())
            .phoneNumber(user.getPhoneNumber())
            .address(user.getAddress())
            .enabled(user.getEnabled())
            .roles(roleNames)
            .createdAt(user.getCreatedAt())
            .updatedAt(user.getUpdatedAt())
            .lastLogin(user.getLastLogin())
            .build();
    }
}
