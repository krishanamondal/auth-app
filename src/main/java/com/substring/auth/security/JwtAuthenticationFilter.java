package com.substring.auth.security;

import com.substring.auth.repository.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private final Logger logger =
            LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = null;

        // ================================
        // 1. CHECK AUTH HEADER FIRST
        // ================================
        String authHeader = request.getHeader("Authorization");

        logger.info("Authorization Header: {}", authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
        }

        // ================================
        // 2. CHECK COOKIE IF HEADER EMPTY
        // ================================
        if (jwt == null && request.getCookies() != null) {

            for (Cookie cookie : request.getCookies()) {

                logger.info("Cookie -> {} = {}", cookie.getName(), cookie.getValue());

                // 🔥 ONLY ACCESS TOKEN IS ALLOWED HERE
                if ("accessToken".equals(cookie.getName())) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }

        logger.info("JWT extracted: {}", jwt);

        // ================================
        // 3. NO TOKEN → CONTINUE
        // ================================
        if (jwt == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {

            // ================================
            // 4. VALIDATE ACCESS TOKEN ONLY
            // ================================
            if (!jwtService.isAccessToken(jwt)) {
                logger.warn("Token is NOT access token");
                filterChain.doFilter(request, response);
                return;
            }

            // ================================
            // 5. PARSE TOKEN
            // ================================
            Jws<Claims> parsed = jwtService.parse(jwt);
            Claims claims = parsed.getPayload();

            String userId = claims.getSubject();
            UUID uuid = UUID.fromString(userId);

            // ================================
            // 6. LOAD USER
            // ================================
            userRepository.findById(uuid)
                    .ifPresent(user -> {

                        if (!user.isEnable()) return;

                        List<GrantedAuthority> authorities =
                                user.getRoles() == null
                                        ? List.of()
                                        : user.getRoles()
                                        .stream()
                                        .map(role ->
                                                new SimpleGrantedAuthority(role.getName()))
                                        .collect(Collectors.toList());

                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        user.getEmail(),
                                        null,
                                        authorities
                                );

                        authentication.setDetails(
                                new WebAuthenticationDetailsSource()
                                        .buildDetails(request)
                        );

                        SecurityContextHolder.getContext()
                                .setAuthentication(authentication);
                    });

        } catch (ExpiredJwtException e) {
            logger.error("Token expired: {}", e.getMessage());

        } catch (JwtException e) {
            logger.error("Invalid JWT: {}", e.getMessage());

        } catch (Exception e) {
            logger.error("Auth error: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}