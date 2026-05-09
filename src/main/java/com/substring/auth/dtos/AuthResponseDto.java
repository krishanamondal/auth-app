package com.substring.auth.dtos;

import com.substring.auth.controllers.LoginRequestDto;

public record AuthResponseDto (

        String accessToken,
        String refreshToken,
        long expiresIn,
        String tokenType,
        UserDto user){
    public static AuthResponseDto of(String accessToken, String refreshToken, long expiresIn, UserDto user) {
        return new AuthResponseDto(accessToken, refreshToken, expiresIn, "Bearer", user);
    }
}
