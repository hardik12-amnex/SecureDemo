package com.example.secureapp.dpop;

/**
 * Thrown when a DPoP proof JWT fails validation.
 *
 * <p>Caught by {@link DPoPAuthenticationFilter} and translated into an
 * HTTP 401 Unauthorized response.</p>
 */
public class DPoPValidationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DPoPValidationException(String message) {
        super(message);
    }

    public DPoPValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
