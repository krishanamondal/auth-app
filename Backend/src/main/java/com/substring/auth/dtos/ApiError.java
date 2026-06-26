package com.substring.auth.dtos;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

public record ApiError(
        int status,
        String error,
        String message,
        String path,
        String dateTime
) {
        public static ApiError of(int status, String error, String message, String path, String dateTime) {

                return new ApiError(status, error, message, path,dateTime);
        }
//    public static ApiError of(int status, String error, String message, String path,boolean dateTime) {
//        return new ApiError(status, error, message, path, OffsetDateTime.now(ZoneOffset.UTC));
//    }
}
