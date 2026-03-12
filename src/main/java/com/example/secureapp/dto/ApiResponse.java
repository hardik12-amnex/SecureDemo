package com.example.secureapp.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiResponse<T> {

    private boolean success;
    private String message;
    private T data;
    private int statusCode;
    @Default
    private long timestamp = System.currentTimeMillis();

    public static <T> ApiResponse<T> success(String message, T data, int statusCode) {
        return ApiResponse.<T>builder()
            .success(true)
            .message(message)
            .data(data)
            .statusCode(statusCode)
            .build();
    }

    public static <T> ApiResponse<T> error(String message, int statusCode) {
        return ApiResponse.<T>builder()
            .success(false)
            .message(message)
            .statusCode(statusCode)
            .build();
    }
}
