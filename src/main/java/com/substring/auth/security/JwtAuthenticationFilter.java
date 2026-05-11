package com.substring.auth.security;

import com.substring.auth.repository.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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

        final String authHeader =
                request.getHeader("Authorization");

        logger.info("Authorization Header : {}", authHeader);

        // Skip if no Bearer token
        if (authHeader == null ||
                !authHeader.startsWith("Bearer ")) {

            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(7);

        try {

            // Check token type
            if (!jwtService.isAccessToken(jwt)) {
                filterChain.doFilter(request, response);
                return;
            }

            // Parse token
            Jws<Claims> parse = jwtService.parse(jwt);

            Claims payload = parse.getPayload();

            String userId = payload.getSubject();

            UUID userUUID = UUID.fromString(userId);

            userRepository.findById(userUUID)
                    .ifPresent(user -> {

                        if (user.isEnable()) {

                            List<GrantedAuthority> authorities =
                                    user.getRoles() == null
                                            ? List.of()
                                            : user.getRoles()
                                            .stream()
                                            .map(role ->
                                                    new SimpleGrantedAuthority(
                                                            role.getName()))
                                            .collect(Collectors.toList());

                            UsernamePasswordAuthenticationToken authentication =
                                    new UsernamePasswordAuthenticationToken(
                                            user.getEmail(),
                                            null,
                                            authorities
                                    );

                            authentication.setDetails(
                                    new WebAuthenticationDetailsSource()
                                            .buildDetails(request));

                            if (SecurityContextHolder
                                    .getContext()
                                    .getAuthentication() == null) {

                                SecurityContextHolder
                                        .getContext()
                                        .setAuthentication(authentication);
                            }
                        }
                    });

        } catch (ExpiredJwtException e) {

            logger.error("JWT expired: {}", e.getMessage());
            request.setAttribute("error","Token Expire");

        } catch (MalformedJwtException e) {

            logger.error("Invalid JWT: {}", e.getMessage());
            request.setAttribute("error","Invalid Token");

        } catch (JwtException e) {

            logger.error("JWT error: {}", e.getMessage());
            request.setAttribute("error","Invalid Token");

        } catch (Exception e) {

            logger.error("Authentication failed: {}", e.getMessage());
            request.setAttribute("error","Invalid Token");

        }

        filterChain.doFilter(request, response);
    }
}