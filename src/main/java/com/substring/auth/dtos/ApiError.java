package com.substring.auth.dtos;

import java.time.OffsetDateTime;

public record ApiError(
        int status,
        String error,
        String message,
        String path,
        OffsetDateTime timestamp
) {
        public static ApiError of(int status, String error, String message, String path) {
            return new ApiError(status, error, message, path, OffsetDateTime.now());
        }
}
