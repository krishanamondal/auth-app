package com.substring.auth.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
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

    public void addRefreshCookie(HttpServletResponse response,String value,int maxAge){
        var responseCookieBuilder = ResponseCookie.from(refreshTokenCookieName, value)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .domain(cookieDomin)
                .path("/")
                .maxAge(maxAge)
                .sameSite(cookieSameSite);
        if (cookieDomin!=null && !cookieDomin.isBlank()){
            responseCookieBuilder.domain(cookieDomin);
        }
        ResponseCookie responseCookie = responseCookieBuilder.build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());

    }
    public void clearRefreshCookie(HttpServletResponse response){
        ResponseCookie responseCookie = ResponseCookie.from(refreshTokenCookieName, "")
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .domain(cookieDomin)
                .path("/")
                .maxAge(0)
                .sameSite(cookieSameSite)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }
}
