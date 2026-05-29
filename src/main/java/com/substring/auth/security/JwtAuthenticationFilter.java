package com.substring.auth.security;

import com.substring.auth.repository.UserRepository;
import com.substring.auth.repository.RefreshTokenRepository;
import com.substring.auth.security.CookieService;
import com.substring.auth.entities.RefreshToken;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.time.Instant;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    private final Logger logger =
            LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        logger.info("Authorization Header : {}", authHeader);

        String jwt = null;

        // If Authorization header is present and Bearer, use it
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
        } else {
            // Try to read refresh token cookie as fallback for authentication
            try {
                var cookies = request.getCookies();
                if (cookies != null && cookieService != null) {
                    String cookieName = cookieService.getRefreshTokenCookieName();
                    for (var c : cookies) {
                        if (cookieName.equals(c.getName())) {
                            String refreshToken = c.getValue();
                            if (refreshToken != null && !refreshToken.isBlank()) {
                                // validate refresh token format and db record
                                if (jwtService.isRefreshToken(refreshToken)) {
                                    String jti = jwtService.getJti(refreshToken);
                                    refreshTokenRepository.findByJtiWithUser(jti).ifPresent(rt -> {
                                        if (!rt.isRevoked() && rt.getExpiresAt() != null && rt.getExpiresAt().isAfter(Instant.now())) {
                                            // valid refresh token record -> authenticate user
                                            var user = rt.getUser();
                                            if (user != null && user.isEnable()) {
                                                List<GrantedAuthority> authorities =
                                                        user.getRoles() == null
                                                                ? List.of()
                                                                : user.getRoles()
                                                                .stream()
                                                                .map(role -> new SimpleGrantedAuthority(role.getName()))
                                                                .collect(Collectors.toList());

                                                UsernamePasswordAuthenticationToken authentication =
                                                        new UsernamePasswordAuthenticationToken(
                                                                user.getEmail(),
                                                                null,
                                                                authorities);

                                                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                                                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                                                    SecurityContextHolder.getContext().setAuthentication(authentication);
                                                }
                                            }
                                        } else {
                                            request.setAttribute("error", "Refresh token revoked or expired");
                                        }
                                    });
                                } else {
                                    request.setAttribute("error", "Cookie does not contain a valid refresh token");
                                }
                            }
                            break;
                        }
                    }
                }
            } catch (ExpiredJwtException e) {
                logger.error("Refresh JWT expired: {}", e.getMessage());
                request.setAttribute("error", "Token Expire");
            } catch (MalformedJwtException e) {
                logger.error("Invalid JWT (cookie): {}", e.getMessage());
                request.setAttribute("error", "Invalid Token");
            } catch (JwtException e) {
                logger.error("JWT cookie error: {}", e.getMessage());
                request.setAttribute("error", "Invalid Token");
            } catch (Exception e) {
                logger.error("Authentication failed (cookie): {}", e.getMessage());
                request.setAttribute("error", "Invalid Token");
            }
        }

        // If we found an Authorization Bearer access token, validate it and set auth
        if (jwt != null) {
            try {
                // Check token type
                if (!jwtService.isAccessToken(jwt)) {
                    // Not an access token
                } else {
                    // Parse token
                    Jws<Claims> parse = jwtService.parse(jwt);
                    Claims payload = parse.getPayload();
                    String userId = payload.getSubject();
                    UUID userUUID = UUID.fromString(userId);
                    userRepository.findById(userUUID).ifPresent(user -> {
                        if (user.isEnable()) {
                            List<GrantedAuthority> authorities =
                                    user.getRoles() == null
                                            ? List.of()
                                            : user.getRoles()
                                            .stream()
                                            .map(role -> new SimpleGrantedAuthority(role.getName()))
                                            .collect(Collectors.toList());

                            UsernamePasswordAuthenticationToken authentication =
                                    new UsernamePasswordAuthenticationToken(
                                            user.getEmail(),
                                            null,
                                            authorities
                                    );

                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                                SecurityContextHolder.getContext().setAuthentication(authentication);
                            }
                        }
                    });
                }

            } catch (ExpiredJwtException e) {
                logger.error("JWT expired: {}", e.getMessage());
                request.setAttribute("error", "Token Expire");
            } catch (MalformedJwtException e) {
                logger.error("Invalid JWT: {}", e.getMessage());
                request.setAttribute("error", "Invalid Token");
            } catch (JwtException e) {
                logger.error("JWT error: {}", e.getMessage());
                request.setAttribute("error", "Invalid Token");
            } catch (Exception e) {
                logger.error("Authentication failed: {}", e.getMessage());
                request.setAttribute("error", "Invalid Token");
            }
        }

        filterChain.doFilter(request, response);
    }
}