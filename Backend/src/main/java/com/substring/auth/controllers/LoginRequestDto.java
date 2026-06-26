package com.substring.auth.controllers;

import com.substring.auth.dtos.UserDto;

public record LoginRequestDto (
        String email,
        String password
){

}


