package com.substring.auth.dtos;

import lombok.Getter;
import lombok.Setter;


public record RefreshTokenRequest(
        String refreshToken
) {
}
