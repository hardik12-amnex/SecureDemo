package com.example.secureapp.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for the login endpoint.
 *
 * <p>Contains the user profile data and token metadata. The JWT access token
 * itself is NOT included in the response body — it is set as an HttpOnly
 * cookie by the server, making it inaccessible to JavaScript (XSS-proof).</p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {

    /** Token expiration time in milliseconds. */
    private long expiresIn;

    /** The authenticated user's profile information. */
    private UserResponse user;
}