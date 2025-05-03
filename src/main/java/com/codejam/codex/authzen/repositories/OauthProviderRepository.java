package com.codejam.codex.authzen.repositories;

import com.codejam.codex.authzen.models.OauthProvider;
import com.codejam.codex.authzen.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthProviderRepository extends JpaRepository<OauthProvider, Long> {
    Optional<OauthProvider> findByProviderAndExternalUserId(String provider, String externalUserId);

    // Add this method
    Optional<OauthProvider> findByProviderAndUser(String provider, User user);
}
