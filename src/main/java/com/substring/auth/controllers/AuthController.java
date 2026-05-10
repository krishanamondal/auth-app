package com.substring.auth.controllers;

import com.substring.auth.dtos.AuthResponseDto;
import com.substring.auth.dtos.UserDto;
import com.substring.auth.entities.User;
import com.substring.auth.repository.UserRepository;
import com.substring.auth.security.JwtService;
import com.substring.auth.services.AuthService;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> loginUser(@RequestBody LoginRequestDto loginDto){
        Authentication authenticated = authenticate(loginDto);
        User user = userRepository.findByEmail(loginDto.email()).orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        if (!user.isEnable()){
            throw  new DisabledException("User account is disabled");
        }
        String accessToken = jwtService.generateAccessToken(user);
        AuthResponseDto authResponse = AuthResponseDto.of(accessToken, "", jwtService.getAccessTokenExpirationTime(), modelMapper.map(user, UserDto.class));
        return ResponseEntity.ok(authResponse);
    }
    private Authentication authenticate(LoginRequestDto dto){
        try {
          return   authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(dto.email(), dto.password())
            );
        }catch (Exception exception){
    throw new BadCredentialsException("Invalid email or password");
        }
    }

    {
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
