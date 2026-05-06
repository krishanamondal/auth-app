package com.substring.auth.security;

import com.substring.auth.repository.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
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
    private Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
      logger.info("Authorization Header : {}",authHeader);
        // 1. Check if the Authorization header is present and starts with "Bearer "
        if (authHeader != null && !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
        }

        String jwt = authHeader.substring(7);


        try {
            if (!jwtService.isAccessToken(jwt)){
                filterChain.doFilter(request,response);
                return;
            }
            Jws<Claims> parse = jwtService.parse(jwt);
            Claims payload = parse.getPayload();

            String userId = payload.getSubject();
//            String jti = payload.getId();
            UUID userUUid = UUID.fromString(userId);
            userRepository.findById(userUUid)
                    .ifPresent(user -> {

if (user.isEnable()){
    List<GrantedAuthority> authorities = user.getRoles() == null ? List.of() : user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            user.getEmail(),
            null,
            authorities
    );
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    if (SecurityContextHolder.getContext().getAuthentication() == null){
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}


                    });


        } catch (ExpiredJwtException exception){
            exception.printStackTrace();
        }catch (MalformedJwtException exception){
            exception.printStackTrace();
        }catch (JwtException exception){
            exception.printStackTrace();
        }catch (Exception e) {
            // If token is invalid or expired, we don't set the context
            // Spring Security will eventually throw a 403 or 401 based on your config
            System.out.println("JWT Authentication failed: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}