package com.codejam.codex.authzen.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Service
public class OAuthService {

    @Value("${github.client-id}")
    private String clientId;

    @Value("${github.client-secret}")
    private String clientSecret;

    @Value("${github.redirect-uri}")
    private String redirectUri;

    private final RestTemplate restTemplate = new RestTemplate();

    public String getGithubAccessToken(String code) {
        String url = "https://github.com/login/oauth/access_token"; // Corrected URL

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));

        Map<String, String> body = Map.of(
                "client_id", clientId,
                "client_secret", clientSecret,
                "code", code,
                "redirect_uri", redirectUri
        );

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            Object token = response.getBody().get("access_token"); // Corrected key
            if (token != null) {
                return token.toString();
            } else {
                 throw new RuntimeException("Access token not found in GitHub response.");
            }
        } else {
            // Consider more specific exception handling or logging
            throw new RuntimeException("Failed to get GitHub access token. Status: " + response.getStatusCode());
        }
    }

    public Map<String, Object> getGithubUser(String accessToken) {
        String url = "https://api.github.com/user";
        // Removed incorrect URL modification: url+=accessToken;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON)); // Good practice to set Accept header

        HttpEntity<Void> request = new HttpEntity<>(headers);

        // Corrected HTTP method to GET and specified response type
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url,
                HttpMethod.GET, // Corrected method
                request,
                (Class<Map<String, Object>>)(Class<?>)Map.class // Cast for clarity
        );

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return response.getBody();
        } else {
             // Consider more specific exception handling or logging
            throw new RuntimeException("Failed to get GitHub user info. Status: " + response.getStatusCode());
        }
    }
}
