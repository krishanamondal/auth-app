package com.substring.auth.services.impl;

import com.substring.auth.dtos.UserDto;
import com.substring.auth.entities.Provider;
import com.substring.auth.entities.User;
import com.substring.auth.exceptions.ResourceNotFoundException;
import com.substring.auth.helpers.UserHelper;
import com.substring.auth.repository.UserRepository;
import com.substring.auth.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is required");
        }if (userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("Email already exists");
        }
//
        User user = modelMapper.map(userDto, User.class);
        user.setProvider(userDto.getProvider()!=null ? userDto.getProvider() : Provider.LOCAL);
        // role assign here to user__ for authorization

        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("user not found this email : "+email));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uuid = UserHelper.parseUUID(userId);
        User existingUser = userRepository
                .findById(uuid)
                .orElseThrow(() -> new ResourceNotFoundException("User Not Found Given Id"));
        if (userDto.getName() != null) existingUser.setName(userDto.getName());
        if (userDto.getImage() != null) existingUser.setImage(userDto.getImage());
        if (userDto.getProvider() != null) existingUser.setProvider(userDto.getProvider());
        if (userDto.getPassword() != null) existingUser.setPassword(userDto.getPassword());
        existingUser.setUpdatedAt(Instant.now());
        existingUser.setEnable(userDto.isEnable());
        User user = userRepository.save(existingUser);
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uid = UserHelper.parseUUID(userId);
        User user = userRepository
                .findById(uid)
                .orElseThrow(() -> new ResourceNotFoundException("User Not Found Given Id"));
        userRepository.delete(user);
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user = userRepository.findById(UserHelper.parseUUID(userId)).orElseThrow(() -> new ResourceNotFoundException("User Not Found Given Id"));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }
}
