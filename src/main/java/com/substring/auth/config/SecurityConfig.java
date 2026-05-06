package com.substring.auth.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.auth.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

@Configuration
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http){
        http.cors(Customizer.withDefaults())
        .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorizeHttpRequest ->
        authorizeHttpRequest.requestMatchers("/api/v1/auth/**").permitAll()
        .anyRequest().authenticated())
        .csrf(AbstractHttpConfigurer::disable)
        .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint((req, response, authException)->{

            logger.warn("Unauthorized access attempt: {}", authException.getMessage());
            response.setStatus(401);
            response.setContentType("application/json");
            String message = "unauthorize access " + authException.getMessage();
            Map<String, String> errorMap = Map.of(
                    "message", message,
                    "status", String.valueOf(401),
                    "statusCode", "UNAUTHORIZED Please provide valid credentials"
            );
            var objectMapper = new ObjectMapper();
            response.getWriter().write(objectMapper.writeValueAsString(errorMap));

        }))
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }


//    @Bean
//    public UserDetailsService user(){
//        User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
//
//        UserDetails user1 = userBuilder.username("pujus").password("jus").roles("ADMIN").build();
//        UserDetails user2 = userBuilder.username("john").password("doe").roles("USER").build();
//    return new InMemoryUserDetailsManager(user1, user2);
//    }
}
