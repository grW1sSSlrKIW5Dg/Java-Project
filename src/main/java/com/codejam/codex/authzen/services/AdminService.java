package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.DelegateRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleUpdateRequest;
import com.codejam.codex.authzen.dtos.outputs.AuditLogResponse;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.AuditLog;
import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.models.UserRole;
import com.codejam.codex.authzen.repositories.AuditLogRepository;
import com.codejam.codex.authzen.repositories.RoleRepository;
import com.codejam.codex.authzen.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditLogRepository auditLogRepository;

    public List<UserResponse> getAllUsers(String adminUsername) {
        logAction(adminUsername, "User list got successfully");

        return userRepository.findAll()
                .stream()
                .map(user -> {
                    List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
                    return UserResponse.fromEntity(user, permissionNames);
                })
                .toList();
    }

    public UpdateUserResponse updateUserRoles(Long userId, RoleUpdateRequest request, String adminUsername) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        // Assuming role names are unique and request contains the name of the single role to assign.
        // Fetch the specific role. Throw exception if not found.
        Role roleToAssign = roleRepository.findByName(request.getRoleName())
                .stream()
                .findFirst() // Assuming findByName returns a List, take the first if found
                .orElseThrow(() -> new RuntimeException("Role not found: " + request.getRoleName()));

        // Clear existing roles before assigning the new one
        user.getUserRoles().clear();

        // Assign the new role
        UserRole newUserRole = new UserRole();
        newUserRole.setUser(user);
        newUserRole.setRole(roleToAssign);
        user.getUserRoles().add(newUserRole);


        userRepository.save(user);
        logAction(adminUsername, "User roles updated successfully for user ID: " + userId + " to role: " + request.getRoleName());
        return UpdateUserResponse.fromEntity(user);
    }


    public List<AuditLogResponse> getAuditLogs(String adminUsername) {
        logAction(adminUsername, "Audit logs accessed");

        List<AuditLog> auditLogs = auditLogRepository.findAll();

        return auditLogs.stream()
                .map(log -> AuditLogResponse.builder()
                        .id(log.getId())
                        .username(log.getUser().getUsername())
                        .actionType(log.getActionType())
                        .ipAddress(log.getIpAddress())
                        .timestamp(log.getTimestamp())
                        .build())
                .toList();
    }





    public String createRole(RoleRequest request, String adminUsername) {

        if (roleRepository.existsByName(request.getRoleName())) {
            throw new IllegalArgumentException("Role already exists");
        }

        Role role = new Role();
        role.setName(request.getRoleName());
        role.setDescription(request.getDescription());

        roleRepository.save(role);

        logAction(adminUsername, "Role created successfully");

        return "Role created successfully";
    }



    public String delegatePermissions(DelegateRequest request, String adminUsername) {
       User user = userRepository.findById(request.getUserId())
        .orElseThrow(() -> new RuntimeException("User not found"));

        Role role = roleRepository.findByName(request.getRole())
            .stream()
            .findFirst()
            .orElseThrow(() -> new RuntimeException("Role not found: " + request.getRole()));

        boolean alreadyAssigned = user.getUserRoles()
            .stream()
            .anyMatch(userRole -> userRole.getRole().getName().equals(request.getRole()));
        
        if (alreadyAssigned) {
            return "User already has this role";
        }

        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(role);
        user.getUserRoles().add(userRole);
        
        userRepository.save(user);
        
        logAction(adminUsername, "Permissions delegated successfully. Role: " + request.getRole() + 
                ", Reason: " + request.getReason());

        return "Permissions delegated successfully";
    }


    private void logAction(String adminUsername, String actionType) {
        User adminUser = userRepository.findByUsername(adminUsername)
                .orElseThrow(() -> new RuntimeException("Admin user not found"));

        AuditLog log = new AuditLog();
        log.setUser(adminUser);
        log.setActionType(actionType);
        log.setTimestamp(new Timestamp(System.currentTimeMillis()));

        auditLogRepository.save(log);
    }


    public UserResponse getUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());

        return UserResponse.fromEntity(user, permissionNames);
    }



}
