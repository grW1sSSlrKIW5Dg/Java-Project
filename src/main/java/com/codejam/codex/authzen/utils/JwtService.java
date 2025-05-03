package com.codejam.codex.authzen.utils;

import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-token.expiry-ms}")
    private long accessTokenExpiry;

    @Value("${jwt.refresh-token.expiry-ms}")
    private long refreshTokenExpiry;

    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    @PostConstruct
    public void validateSecretLength() {
        if (jwtSecret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("JWT secret key must be at least 32 bytes (256 bits) long.");
        }
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserResponse userDetails) {
        try {
            final String username = extractUsername(token);
            return (username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token) && !isTokenBlacklisted(token));
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Token validation failed for user {}: {}", userDetails.getUsername(), e.getMessage());
            return false;
        }
    }

    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return !isTokenBlacklisted(token);
        } catch (ExpiredJwtException e) {
            logger.debug("Token is expired: {}", e.getMessage());
            return false;
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Token parsing failed: {}", e.getMessage());
            return false;
        }
    }

    public String generateAccessToken(UserResponse userResponse) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userResponse.getId());
        claims.put("username", userResponse.getUsername());
        claims.put("roles", userResponse.getRoles());
        claims.put("permissions", userResponse.getPermissions());
        return buildToken(claims, userResponse.getUsername(), accessTokenExpiry);
    }

    public String generateRefreshToken(UserResponse userDetails) {
        return buildToken(new HashMap<>(), userDetails.getUsername(), refreshTokenExpiry);
    }

    private String buildToken(Map<String, Object> claims, String subject, long expiry) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiry))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Could not determine token expiration: {}", e.getMessage());
            return true;
        }
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .setAllowedClockSkewSeconds(2)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public List<String> extractPermissions(String token) {
        Claims claims = extractAllClaims(token);
        List<?> permissionsObj = claims.get("permissions", List.class);
        if (permissionsObj == null) {
            return Collections.emptyList();
        }
        List<String> permissions = new ArrayList<>();
        for (Object perm : permissionsObj) {
            if (perm instanceof String) {
                permissions.add((String) perm);
            } else {
                logger.warn("Non-string permission found in token: {}", perm);
            }
        }
        return permissions;
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }
}