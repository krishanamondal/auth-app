package com.substring.auth.controllers;

import com.substring.auth.dtos.AuthResponseDto;
import com.substring.auth.dtos.RefreshTokenRequest;
import com.substring.auth.dtos.UserDto;
import com.substring.auth.entities.RefreshToken;
import com.substring.auth.entities.User;
import com.substring.auth.repository.RefreshTokenRepository;
import com.substring.auth.repository.UserRepository;
import com.substring.auth.security.CookieService;
import com.substring.auth.security.JwtService;
import com.substring.auth.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> loginUser(@RequestBody LoginRequestDto loginDto, HttpServletResponse response) {
        Authentication authenticated = authenticate(loginDto);
        User user = userRepository.findByEmail(loginDto.email()).orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        if (!user.isEnable()) {
            throw new DisabledException("User account is disabled");
        }
        String jti = UUID.randomUUID().toString();
         var refreshTokenObject = RefreshToken.builder()
                 .jti(jti)
                 .user(user)
                 .createdAt(Instant.now())
                 .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTokenExpirationTime()))
                 .revoked(false)
                 .build();
        refreshTokenRepository.save(refreshTokenObject);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user,refreshTokenObject.getJti());
        cookieService.addRefreshCookie(response,refreshToken,(int) jwtService.getRefreshTokenExpirationTime());
        cookieService.addNoStoreHeader(response);
        AuthResponseDto authResponse = AuthResponseDto.of(accessToken, refreshToken, jwtService.getAccessTokenExpirationTime(), modelMapper.map(user, UserDto.class));
        return ResponseEntity.ok(authResponse);
    }

    private Authentication authenticate(LoginRequestDto dto) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(dto.email(), dto.password()));
    }
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDto> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest body, HttpServletResponse response, HttpServletRequest request
            ){
        String refreshToken = readRefreshTokenFromRequest(body, request).orElseThrow(() -> new BadCredentialsException("Refresh token is required"));
        if (!jwtService.isRefreshToken(refreshToken)){
            throw new BadCredentialsException("Invalid Refresh Token");
        }
        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElseThrow( () -> new BadCredentialsException("Refresh Token False"));
        if (storedRefreshToken.isRevoked() || storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token is revoked or expired");
        }

        if (storedRefreshToken.getExpiresAt().isBefore(Instant.now())){
            throw new BadCredentialsException("Refresh token is expired");
        }
        if (!storedRefreshToken.getUser().getId().equals(userId)){
            throw new BadCredentialsException("Refresh token does not belong to the user");
        }
         storedRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplaceByToken(newJti);
         refreshTokenRepository.save(storedRefreshToken);
        User user = storedRefreshToken.getUser();
        var newRefreshTokenDB = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTokenExpirationTime()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(newRefreshTokenDB);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user,newJti);
        cookieService.addRefreshCookie(response,newRefreshToken,(int) jwtService.getRefreshTokenExpirationTime());
        cookieService.addNoStoreHeader(response);
        return ResponseEntity.ok(AuthResponseDto.of(newAccessToken,newRefreshToken,jwtService.getAccessTokenExpirationTime(),modelMapper.map(user,UserDto.class)));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response){
        String refreshToken = readRefreshTokenFromRequest(null, request).orElse(null);
        if (refreshToken != null && jwtService.isRefreshToken(refreshToken)){
            String jti = jwtService.getJti(refreshToken);
            refreshTokenRepository.findByJti(jti).ifPresent(rt -> {
                rt.setRevoked(true);
                refreshTokenRepository.save(rt);
            });
        }
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
        return ResponseEntity.noContent().build();
    }
    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        if (request.getCookies() != null) {
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(c -> cookieService.getRefreshTokenCookieName()
                            .equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();
            if (fromCookie.isPresent()) {
                return fromCookie;
            }
        }
        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }
        String refreshHeader = request.getHeader("X-Refresh-Token");
        if (refreshHeader != null && !refreshHeader.isBlank()) {
            return Optional.of(refreshHeader.trim());
        }
        //Authorization -> Bearer Token

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = authHeader.substring(7).trim();
            if (!token.isBlank()) {
                try {
                    if (jwtService.isRefreshToken(token)){
                        return Optional.of(token);
                    }
                }catch (Exception ignored){

                }
            }
        }
        return Optional.empty();
    }
    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
