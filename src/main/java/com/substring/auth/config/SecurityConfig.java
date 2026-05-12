package com.substring.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.auth.dtos.ApiError;
import com.substring.auth.security.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;
import java.util.Map;

@Configuration
public class SecurityConfig {

    private static final Logger logger =
            LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)
            throws Exception {

        http
                .cors(Customizer.withDefaults())

                .csrf(AbstractHttpConfigurer::disable)

                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth ->
                        auth
                                .requestMatchers("/api/v1/auth/**")
                                .permitAll()
                                .anyRequest()
                                .authenticated())

                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(
                                (req, response, authException) -> {

                                    logger.warn(
                                            "Unauthorized access: {}",
                                            authException.getMessage());
                                    String message;
 Object error = req.getAttribute("error");
 if (error != null) {
        message = error.toString();
    } else {
        message = "Unauthorized access";
 }
                                    response.setStatus(
                                            HttpServletResponse.SC_UNAUTHORIZED);

                                    response.setContentType("application/json");

//                                    Map<String, String> errorMap = Map.of(
//                                            "message",
//                                            message,
//                                            "status",
//                                            "401",
//                                            "error",
//                                            "UNAUTHORIZED"
//                                    );
                                    Instant instant = Instant.now();
                                    String time = instant.toString();
var errorMap = ApiError.of(401, "Authorization Access ! ",message,req.getRequestURI(),time);
                                    ObjectMapper objectMapper =
                                            new ObjectMapper();

                                    response.getWriter().write(
                                            objectMapper.writeValueAsString(
                                                    errorMap));
                                }))

                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}