package com.substring.auth.security;

import com.substring.auth.entities.Role;
import com.substring.auth.entities.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Service
@Getter
@Setter
public class JwtService {
    private final SecretKey key;
    private final long accessTokenExpirationTime;
    private final long refreshTokenExpirationTime;
    private final String issuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.accessTokenExpirationTime}") long accessTokenExpirationTime,
            @Value("${security.jwt.refreshTokenExpirationTime}") long refreshTokenTtlSecond,
            @Value("${security.jwt.issuer}") String issuer) {

        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException("Secret key must be at least 32 characters long");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationTime = accessTokenExpirationTime;
        this.refreshTokenExpirationTime = refreshTokenTtlSecond;
        this.issuer = issuer;
    }

    // generate access token
    public String generateAccessToken(User user){
        Instant instant = Instant.now();
        List<String> roles = user.getRoles().stream().map(Role::getName).toList();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(instant))
                .expiration(Date.from(instant.plusSeconds(accessTokenExpirationTime)))
                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles", roles,
                        "typ", "access"
                ))
                .signWith(key)
                .compact();
    }


    public String generateRefreshToken(User user, String jti){
        Instant instant = Instant.now();
        List<String> roles = user.getRoles().stream().map(Role::getName).toList();
        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(instant))
                .expiration(Date.from(instant.plusSeconds(refreshTokenExpirationTime)))
                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles", roles,
                        "typ", "refresh"
                ))
                .signWith(key)
                .compact();
    }

    //    parse the token
    public Jws<Claims> parse(String token){
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
        }catch (JwtException exception){
            throw new IllegalArgumentException("Invalid token");
        }
    }

    public boolean isAccessToken(String token){
        Claims claims = parse(token).getPayload();
        return "access".equals(claims.get("typ"));
    }
    public boolean isRefreshToken(String token){
        Claims claims = parse(token).getPayload();
        return "refresh".equals(claims.get("typ"));
    }

    public UUID getUserId(String token){
        Claims claims = parse(token).getPayload();
        return UUID.fromString(claims.getSubject());
    }
    public String getJti(String token){
        return parse(token).getPayload().getId();
    }
   public List<String> getRole (String token){
        Claims claims = parse(token).getPayload();
        return (List<String>) claims.get("roles");
   }

   public String getEmail (String token){
        Claims claims = parse(token).getPayload();
        return (String) claims.get("email");
   }
}