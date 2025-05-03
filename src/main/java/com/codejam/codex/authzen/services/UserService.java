package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.UpdateUserRequest;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserResponse loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));

        Set<String> roles = user.getUserRoles()
            .stream()
            .map(userRole -> userRole.getRole().getName())
            .collect(Collectors.toSet());

        return UserResponse.builder()
            .id(user.getId())
            .email(user.getEmail())
            .username(user.getUsername())
            .roles(roles)
            .build();
    }


    public UserResponse getProfile(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        
        List<String> permissionNames = userRepository.findPermissionNamesByUsername(username);
        
        return UserResponse.fromEntity(user, permissionNames);
    }

    @Transactional
    public UpdateUserResponse updateUser(String username, UpdateUserRequest updateRequest) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        if (updateRequest.getUsername() != null && !updateRequest.getUsername().isBlank() && !updateRequest.getUsername().equals(user.getUsername())) {
            // Check if the new username already exists
            Optional<User> existingUserByUsername = userRepository.findByUsername(updateRequest.getUsername());
            if (existingUserByUsername.isPresent()) {
                throw new IllegalArgumentException("Username already taken: " + updateRequest.getUsername());
            }
            user.setUsername(updateRequest.getUsername());
        }

        if (updateRequest.getEmail() != null && !updateRequest.getEmail().isBlank() && !updateRequest.getEmail().equals(user.getEmail())) {
             // Check if the new email already exists
            Optional<User> existingUserByEmail = userRepository.findByEmail(updateRequest.getEmail());
            if (existingUserByEmail.isPresent()) {
                throw new IllegalArgumentException("Email already taken: " + updateRequest.getEmail());
            }
            user.setEmail(updateRequest.getEmail());
        }

        if (updateRequest.getPassword() != null && !updateRequest.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(updateRequest.getPassword()));
        }

        user = userRepository.save(user);
        
        return UpdateUserResponse.fromEntity(user);
    }

}
