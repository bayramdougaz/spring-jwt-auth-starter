package dev.bayram.auth.auth;

import java.time.Instant;

import dev.bayram.auth.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

/**
 * Server-side record of an issued refresh token. Only a SHA-256 hash is stored, so a
 * leaked database does not leak usable tokens. Each token is single-use (rotated on refresh).
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 64)
	private String tokenHash;

	@ManyToOne(fetch = FetchType.EAGER, optional = false)
	private User user;

	@Column(nullable = false)
	private Instant expiresAt;

	private Instant revokedAt;

	protected RefreshToken() {
	}

	public RefreshToken(String tokenHash, User user, Instant expiresAt) {
		this.tokenHash = tokenHash;
		this.user = user;
		this.expiresAt = expiresAt;
	}

	public boolean isActive() {
		return revokedAt == null && Instant.now().isBefore(expiresAt);
	}

	public void revoke() {
		if (revokedAt == null) {
			revokedAt = Instant.now();
		}
	}

	public User getUser() {
		return user;
	}

}
