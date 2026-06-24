package com.substring.auth.security;

import com.substring.auth.entities.Provider;
import com.substring.auth.entities.RefreshToken;
import com.substring.auth.entities.User;
import com.substring.auth.repository.RefreshTokenRepository;
import com.substring.auth.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.security.autoconfigure.SecurityProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {
    private final Logger logger = LoggerFactory.getLogger(OAuthSuccessHandler.class);
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    public OAuthSuccessHandler(UserRepository userRepository, JwtService jwtService, CookieService cookieService, RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.cookieService = cookieService;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Authentication successful for user: {}", authentication.getName());
        logger.info(authentication.toString());

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";
        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }
        logger.info("registrationId: {}", registrationId);
        logger.info("User attributes: {}", oAuth2User.getAttributes().toString());

        // 1. Declare the user reference variable
        final User finalUser;

        switch (registrationId) {
            case "google" -> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();

                // 2. Look up by email first
                java.util.Optional<User> existingUser = userRepository.findByEmail(email);

                if (existingUser.isPresent()) {
                    logger.info("User already exists in database");
                    // Use the managed entity from the DB
                    finalUser = existingUser.get();
                } else {
                    logger.info("New user logging in, saving to database...");
                    User newUser = User.builder()
                            .email(email)
                            .name(name) // Tip: You had googleId mapped to name here, changed to name variable
                            .image(picture)
                            .provider(Provider.GOOGLE)
                            .build();
                    // Save and assign the persisted entity (now contains generated ID)
                    finalUser = userRepository.save(newUser);
                }
            }
            default -> {
                throw new RuntimeException("Invalid Registration Id");
            }
        }

        // 3. This will now safely work with the verified, database-persisted user object
        String jti = UUID.randomUUID().toString();
        RefreshToken refreshTokenOB = RefreshToken.builder()
                .jti(jti)
                .user(finalUser)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTokenExpirationTime()))
                .build();

        refreshTokenRepository.save(refreshTokenOB);

        String accessToke = jwtService.generateAccessToken(finalUser);
        String refreshToken = jwtService.generateRefreshToken(finalUser, refreshTokenOB.getJti());
        cookieService.addRefreshCookie(response, refreshToken, (int) jwtService.getRefreshTokenExpirationTime());
        response.getWriter().write("Authentication successful");
    }
}