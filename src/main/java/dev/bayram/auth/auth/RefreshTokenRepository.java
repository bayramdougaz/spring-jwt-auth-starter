package dev.bayram.auth.auth;

import java.time.Instant;
import java.util.Optional;

import dev.bayram.auth.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

	Optional<RefreshToken> findByTokenHash(String tokenHash);

	@Modifying
	@Query("update RefreshToken t set t.revokedAt = :now where t.user = :user and t.revokedAt is null")
	int revokeAllForUser(User user, Instant now);

}
