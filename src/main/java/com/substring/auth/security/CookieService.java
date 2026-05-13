package com.substring.auth.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CookieService {
    private final String refreshTokenCookieName ;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomin;
    private final String cookieSameSite;

    public CookieService(
            @Value("${security.refresh-token-cookie-name}") String refreshTokenCookieName,
            @Value("${security.cookie-http-only}") boolean cookieHttpOnly,
            @Value("${security.cookie-secure}")boolean cookieSecure,
            @Value("${security.cookie-domain}")String cookieDomin,
            @Value("${security.cookie-same-site}")String cookieSameSite) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieDomin = cookieDomin;
        this.cookieSameSite = cookieSameSite;
    }

    
}
