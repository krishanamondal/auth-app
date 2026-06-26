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

    private static final Logger logger =
            LoggerFactory.getLogger(OAuthSuccessHandler.class);

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    public OAuthSuccessHandler(
            UserRepository userRepository,
            JwtService jwtService,
            CookieService cookieService,
            RefreshTokenRepository refreshTokenRepository
    ) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.cookieService = cookieService;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        logger.info("Authentication successful for user: {}",
                authentication.getName());

        OAuth2User oAuth2User =
                (OAuth2User) authentication.getPrincipal();

        String registrationId = "unknown";

        if (authentication instanceof OAuth2AuthenticationToken token) {
            registrationId =
                    token.getAuthorizedClientRegistrationId();
        }

        logger.info("Registration ID: {}", registrationId);
        logger.info("User Attributes: {}",
                oAuth2User.getAttributes());

        User user;

        switch (registrationId) {

            case "google" -> {

                String email = oAuth2User.getAttribute("email");
                String name = oAuth2User.getAttribute("name");
                String picture = oAuth2User.getAttribute("picture");

                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .image(picture)
                        .provider(Provider.GOOGLE)
                        .build();

                user = userRepository.findByEmail(email)
                        .orElseGet(() -> userRepository.save(newUser));
            }

            case "github" -> {

                String login = oAuth2User.getAttribute("login");
                String avatarUrl =
                        oAuth2User.getAttribute("avatar_url");

                String email =
                        oAuth2User.getAttribute("email");

                // GitHub may return null email
                if (email == null || email.isBlank()) {
                    email = login + "@github.local";
                }

                String finalEmail = email;

                User newUser = User.builder()
                        .email(finalEmail)
                        .name(login)
                        .image(avatarUrl)
                        .provider(Provider.GITHUB)
                        .build();

                user = userRepository.findByEmail(finalEmail)
                        .orElseGet(() -> userRepository.save(newUser));
            }

            default ->
                    throw new IllegalArgumentException(
                            "Unsupported OAuth provider: "
                                    + registrationId
                    );
        }

        // Generate refresh token
        String jti = UUID.randomUUID().toString();

        RefreshToken refreshTokenEntity =
                RefreshToken.builder()
                        .jti(jti)
                        .user(user)
                        .revoked(false)
                        .createdAt(Instant.now())
                        .expiresAt(
                                Instant.now().plusSeconds(
                                        jwtService.getRefreshTokenExpirationTime()
                                )
                        )
                        .build();

        refreshTokenRepository.save(refreshTokenEntity);

        // Generate JWT tokens
        String accessToken =
                jwtService.generateAccessToken(user);

        String refreshToken =
                jwtService.generateRefreshToken(
                        user,
                        refreshTokenEntity.getJti()
                );

        // Store refresh token in HttpOnly cookie
        cookieService.addRefreshCookie(
                response,
                refreshToken,
                (int) jwtService.getRefreshTokenExpirationTime()
        );

        // Return access token
        response.setContentType("application/json");

        response.getWriter().write(
                """
                {
                    "accessToken":"%s"
                }
                """.formatted(accessToken)
        );
    }
}