package com.substring.auth.services;

import com.substring.auth.dtos.UserDto;

import java.util.UUID;

public interface UserService {
    UserDto createUser(UserDto userDto);
    UserDto getUserByEmail(String email);
    UserDto updateUser(UserDto userDto, String userId);
        void deleteUser(String userId);
        boolean existsByEmail(String email);
        UserDto getUserById(String userId);
       //get all user
    Iterable<UserDto> getAllUsers();
}
