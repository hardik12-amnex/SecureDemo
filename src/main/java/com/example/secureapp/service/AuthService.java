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

@Service
@RequiredArgsConstructor
public class AuthService {

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
        User user = userRepository.findByUsername(loginRequest.getUsername())
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadRequestException("Invalid credentials");
        }

        if (!user.getEnabled()) {
            throw new BadRequestException("Account is disabled");
        }

        if (!user.getAccountNonLocked()) {
            throw new BadRequestException("Account is locked");
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
