package com.codejam.codex.authzen.services;

import com.codejam.codex.authzen.dtos.inputs.*;
import com.codejam.codex.authzen.dtos.outputs.TokenResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.models.*;
import com.codejam.codex.authzen.repositories.*;
import com.codejam.codex.authzen.utils.EmailUtil;
import com.codejam.codex.authzen.utils.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;


@Service
public class AuthService {

    private final JwtService jwtService;
    private final UserService userService;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final EmailUtil emailUtil;
    private final EmailTokenRepository emailTokenRepository;
    private final OauthProviderRepository oauthProviderRepository;
    private final OAuthService oAuthService;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    // NOTE: In-memory blacklist is not suitable for production/distributed environments.
    // Consider using a persistent store (e.g., Redis, Database) for reliable blacklisting.
    private final Set<String> blacklistedTokens = new HashSet<>();

    @Autowired
    public AuthService(JwtService jwtService, UserService userService, UserRepository userRepository,
                       BCryptPasswordEncoder passwordEncoder, EmailUtil emailUtil, EmailTokenRepository emailTokenRepository, OauthProviderRepository oauthProviderRepository, OAuthService oAuthService, RoleRepository roleRepository, RefreshTokenRepository refreshTokenRepository) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailUtil = emailUtil;
        this.emailTokenRepository = emailTokenRepository;
        this.oauthProviderRepository = oauthProviderRepository;
        this.oAuthService = oAuthService;
        this.roleRepository = roleRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /**
     * Registers a new user.
     *
     * @param request The registration request containing user details.
     * @return UserResponse containing details of the registered user.
     */
    public UserResponse registerUser(RegisterRequest request) {
        List<Role> roles = roleRepository.findByName("ROLE_USER");
        if (roles.isEmpty()) {
            // Consider creating the role if it doesn't exist or throwing a more specific configuration exception
            throw new RuntimeException("Default role not found: ROLE_USER");
        }
        Role userRole = roles.get(0);

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setActive(true); // Consider if users should be active immediately or require verification
        user.setCreatedAt(new java.sql.Timestamp(System.currentTimeMillis()));
        user.setUserRoles(new HashSet<>()); // Initialize the set

        // Create and associate the UserRole before saving the User
        UserRole userRoleMapping = new UserRole();
        userRoleMapping.setUser(user);
        userRoleMapping.setRole(userRole);
        user.getUserRoles().add(userRoleMapping);

        // Save the user with the role mapping in a single operation
        user = userRepository.save(user);

        // Fetch permissions associated with the user's roles
        List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());

        return UserResponse.fromEntity(user, permissionNames);
    }


    /**
     * Authenticates a user and issues an access token.
     *
     * @param request The login request containing user credentials.
     * @return TokenResponse containing access and refresh tokens if authentication is successful, null otherwise.
     */
    public TokenResponse authenticateUser(LoginRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                // Use the fetched user entity directly
                List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
                UserResponse userResponse = UserResponse.fromEntity(user, permissionNames); // Build UserResponse from the entity

                String accessToken = jwtService.generateAccessToken(userResponse);
                String refreshToken = jwtService.generateRefreshToken(userResponse);
                saveRefreshToken(user, refreshToken);
                return new TokenResponse(accessToken, refreshToken);
            }
        }
        return null; // Consider throwing specific exceptions for failed login (e.g., BadCredentialsException)
    }

    /**
     * Handles OAuth login and generates OAuth token.
     *
     * @param request The OAuth login request containing OAuth credentials.
     * @return TokenResponse containing access and refresh tokens if successful, null otherwise.
     */
    public TokenResponse authenticateOAuth(OAuthRequest request) {
        // TODO: Make provider handling more generic or use a factory/strategy pattern
        if ("github".equalsIgnoreCase(request.getProvider())) {
            String oAuthAccessToken = oAuthService.getGithubAccessToken(request.getOauthToken());
            Map<String, Object> githubUser = oAuthService.getGithubUser(oAuthAccessToken);

            String githubId = githubUser.get("id").toString();
            // Handle potential null email from GitHub
            String githubEmail = (String) githubUser.get("email");
            String githubLogin = (String) githubUser.get("login");

            if (githubEmail == null || githubEmail.isEmpty()) {
                // Decide how to handle users without a public email (e.g., prompt user, use a placeholder)
                throw new RuntimeException("GitHub user email is not available or public.");
            }

            Optional<OauthProvider> providerOpt = oauthProviderRepository.findByProviderAndExternalUserId("github", githubId);
            User user;
            if (providerOpt.isPresent()) {
                user = providerOpt.get().getUser();
            } else {
                // Check if a user with this email already exists (maybe registered directly)
                Optional<User> existingUserOpt = userRepository.findByEmail(githubEmail);
                if (existingUserOpt.isPresent()) {
                    user = existingUserOpt.get();
                    // Link the existing user account to the GitHub provider
                    if (oauthProviderRepository.findByProviderAndUser("github", user).isEmpty()) {
                         oauthProviderRepository.save(OauthProvider.builder()
                            .provider("github")
                            .externalUserId(githubId)
                            .user(user)
                            .build());
                    }
                } else {
                    // Create a new user for this GitHub login
                    List<Role> roles = roleRepository.findByName("ROLE_USER");
                    if (roles.isEmpty()) {
                        throw new RuntimeException("Default role not found: ROLE_USER");
                    }
                    Role userRole = roles.get(0);

                    user = User.builder()
                            .username(githubLogin) // Consider potential username conflicts
                            .email(githubEmail)
                            .isActive(true)
                            .isLocked(false)
                            .createdAt(new java.sql.Timestamp(System.currentTimeMillis()))
                            .userRoles(new HashSet<>())
                            .build();

                    UserRole userRoleMapping = new UserRole();
                    userRoleMapping.setUser(user);
                    userRoleMapping.setRole(userRole);
                    user.getUserRoles().add(userRoleMapping);

                    user = userRepository.save(user); // Save the new user

                    // Save the OAuth provider link
                    oauthProviderRepository.save(OauthProvider.builder()
                            .provider("github")
                            .externalUserId(githubId)
                            .user(user)
                            .build());
                }
            }

            // Use the determined user entity directly
            List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());
            UserResponse userResponse = UserResponse.fromEntity(user, permissionNames); // Build UserResponse from the entity

            String accessToken = jwtService.generateAccessToken(userResponse);
            String refreshToken = jwtService.generateRefreshToken(userResponse);
            saveRefreshToken(user, refreshToken); // Save refresh token for OAuth user as well

            return new TokenResponse(accessToken, refreshToken);
        }
        // TODO: Handle other providers or return an appropriate error/response
        return null;
    }


    /**
     * Sends a password reset email to the user.
     *
     * @param request The reset request containing the user's email.
     * @return true if email was sent successfully, false otherwise.
     */
    public boolean sendPasswordResetEmail(ResetRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isPresent()) {
            User user = userOptional.get();

            // Check if user registered via OAuth and doesn't have a local password set
            // If so, password reset might not be applicable. Decide on the desired behavior.
            // if (user.getPassword() == null || user.getPassword().isEmpty()) {
            //     // Handle case where user has no local password (e.g., OAuth only)
            //     return false; // Or throw an exception, or send a different kind of email
            // }


            EmailToken token = EmailToken.builder()
                    .user(user)
                    .token(UUID.randomUUID().toString())
                    .purpose("RESET_PASSWORD")
                    .expiresAt(Timestamp.from(Instant.now().plus(15, ChronoUnit.MINUTES))) // Expiry duration could be configurable
                    .build();

            emailTokenRepository.save(token);

            // TODO: Make the base URL configurable (e.g., via application properties)
            String resetLink = "http://localhost:8080/reset-password/reset-password.html?token=" + token.getToken();

            String subject = "Password Reset Request";
            // Consider using email templates for better formatting and internationalization
            String body = "You have requested to reset your password. Click the link below to reset your password:\n" + resetLink +
                          "\nIf you did not request this, please ignore this email.";

            // Assuming emailUtil handles the sending logic correctly
            return emailUtil.sendPasswordResetEmail(request.getEmail(), subject, body, resetLink);
        }
        return false;
    }


    /**
     * Resets the user's password using the provided token.
     *
     * @param request The reset password request containing token and new password.
     * @return true if the password was successfully reset, false otherwise.
     */
    public boolean resetUserPassword(ResetPasswordRequest request) {
        Optional<EmailToken> tokenOptional = emailTokenRepository.findByToken(request.getToken());
        if (tokenOptional.isPresent()) {
            EmailToken token = tokenOptional.get();

            // 1. Check expiry
            if (token.getExpiresAt().before(Timestamp.from(Instant.now()))) {
                emailTokenRepository.delete(token); // Clean up expired token
                return false; // Token expired
            }

            // 2. Check purpose
            if (!"RESET_PASSWORD".equals(token.getPurpose())) {
                return false; // Invalid token purpose
            }

            // 3. Get user directly from token
            User user = token.getUser();
            if (user == null) {
                 return false; // Should not happen if DB constraints are set, but good practice to check
            }

            // 4. Optional: Verify email matches (as an extra check against token misuse if email is known)
            if (!user.getEmail().equalsIgnoreCase(request.getEmail())) {
                return false; // Email in request doesn't match user associated with token
            }

            // 5. Update password
            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            // 6. Delete the used token
            emailTokenRepository.delete(token);

            return true;
        }
        return false; // Token not found
    }

    /**
     * Checks if the user is authenticated by validating the token from the request.
     *
     * @param request The HTTP request containing the token.
     * @return true if the user is authenticated, false otherwise.
     */
    public boolean isAuthenticated(HttpServletRequest request) {
        final String token = extractTokenFromHeader(request);
        if (token == null || !jwtService.isTokenValid(token) || isBlacklisted(token)) {
            return false;
        }

        final String username = jwtService.extractUsername(token);
        UserResponse userDetails = userService.loadUserByUsername(username);
        return jwtService.isTokenValid(token, userDetails);
    }

    /**
     * Extracts the token from the HTTP request header.
     *
     * @param request The HTTP request.
     * @return The token if present, null otherwise.
     */
    private String extractTokenFromHeader(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Retrieves the username from the token in the request.
     *
     * @param request The HTTP request containing the token.
     * @return The username extracted from the token, or null if the token is invalid.
     */
    public String getUsername(HttpServletRequest request) {
        final String token = extractTokenFromHeader(request);
        if (token == null || !jwtService.isTokenValid(token) || isBlacklisted(token)) {
            return null;
        }
        return jwtService.extractUsername(token);
    }

    /**
     * Retrieves user details from the username.
     *
     * @param username The username.
     * @return UserResponse with the user's details, or null if the user doesn't exist.
     */
    public UserResponse getUserDetails(String username) {
        try {
            return userService.loadUserByUsername(username);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Saves a refresh token for a user.
     *
     * @param user The user associated with the refresh token.
     * @param token The refresh token to be saved.
     */
    private void saveRefreshToken(User user, String token) {

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(token)
                .revoked(false)
                .expiresAt(Timestamp.from(Instant.now().plus(7, ChronoUnit.DAYS)))
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    /**
     * Refreshes an access token using a valid refresh token.
     *
     * @param refreshToken The refresh token to be used for refreshing the access token.
     * @return TokenResponse containing new access and refresh tokens.
     * @throws RuntimeException if the refresh token is expired or invalid.
     */
    public TokenResponse refreshToken(String refreshToken) {

        RefreshToken tokenRecord = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (tokenRecord.isRevoked() || tokenRecord.getExpiresAt().before(new Timestamp(System.currentTimeMillis()))) {
            throw new RuntimeException("Refresh token is expired or revoked");
        }

        if (!jwtService.isTokenValid(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        String username = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Revoke the old refresh token
        tokenRecord.setRevoked(true);
        refreshTokenRepository.save(tokenRecord);

        List<String> permissionNames = userRepository.findPermissionNamesByUsername(user.getUsername());

        UserResponse userDetails = UserResponse.fromEntity(user, permissionNames);

        String newAccessToken = jwtService.generateAccessToken(userDetails);
        String newRefreshToken = jwtService.generateRefreshToken(userDetails);

        // Save the new refresh token
        saveRefreshToken(user, newRefreshToken);

        return TokenResponse.builder().accessToken(newAccessToken).refreshToken(newRefreshToken).build();
    }

    /**
     * Blacklists the token associated with the incoming request if valid and not already blacklisted.
     * NOTE: This uses an in-memory blacklist, which is lost on restart and not suitable for
     * distributed environments. Use a persistent store (e.g., Redis, Database) for production.
     *
     * @param request HttpServletRequest containing the token to be blacklisted.
     * @return true if the token was successfully added to the blacklist; false if the token is invalid
     *         or already blacklisted.
     */
    public boolean blacklistToken(HttpServletRequest request) {
        String token = extractTokenFromHeader(request);
        // Validate token before blacklisting to avoid storing invalid tokens
        if (token == null || !jwtService.isTokenValid(token)) {
            return false; // Token is invalid or expired, no need to blacklist
        }

        // Check if already blacklisted
        if (isBlacklisted(token)) {
            return false; // Already blacklisted
        }

        // Add to the blacklist
        blacklistedTokens.add(token);
        // Consider logging the blacklisting event
        return true;
    }

    /**
     * Checks if a token is blacklisted.
     * NOTE: Checks against an in-memory blacklist.
     *
     * @param token The token to check.
     * @return true if the token is blacklisted, false otherwise.
     */
    public boolean isBlacklisted(String token) {
        return token != null && blacklistedTokens.contains(token);
    }

    /**
     * Cleans up expired tokens from the in-memory blacklist.
     * NOTE: This method needs to be scheduled (e.g., using @Scheduled annotation and enabling scheduling)
     * to run periodically for the in-memory blacklist to be effective.
     * Using a persistent store with TTL (like Redis) often simplifies expiry management.
     */
    // Add @Scheduled annotation if enabling scheduling (e.g., @Scheduled(fixedRate = 3600000) // Run every hour)
    public void cleanupBlacklist() {
        // Use removeIf for cleaner iteration and removal
        blacklistedTokens.removeIf(token -> {
            try {
                // If the token is no longer valid (e.g., expired), remove it from the blacklist
                return !jwtService.isTokenValid(token);
            } catch (Exception e) {
                // If token parsing fails for any reason, treat it as invalid and remove it
                // Consider logging the exception
                return true;
            }
        });
    }


}
