package com.substring.auth.services.impl;

import com.substring.auth.dtos.UserDto;
import com.substring.auth.services.AuthService;
import com.substring.auth.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserService userService;

     @Override
    public UserDto registerUser(UserDto userDto) {
         UserDto user = userService.createUser(userDto);

         return user;
     }

}
