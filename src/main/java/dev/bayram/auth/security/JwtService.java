package dev.bayram.auth.security;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import javax.crypto.SecretKey;

import dev.bayram.auth.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

/**
 * Issues and validates short-lived, stateless access tokens (HS256-signed JWTs).
 */
@Service
public class JwtService {

	private final JwtProperties props;

	private final SecretKey key;

	public JwtService(JwtProperties props) {
		this.props = props;
		this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(props.secret()));
	}

	public String generateAccessToken(User user) {
		Instant now = Instant.now();
		return Jwts.builder()
			.issuer(props.issuer())
			.subject(user.getEmail())
			.claim("uid", user.getId())
			.claim("role", user.getRole().name())
			.issuedAt(Date.from(now))
			.expiration(Date.from(now.plus(props.accessTokenTtl())))
			.signWith(key)
			.compact();
	}

	/**
	 * Returns the token's subject (the user's email) if the signature, issuer and expiry
	 * are all valid, or empty otherwise.
	 */
	public Optional<String> validateAndGetSubject(String token) {
		try {
			Claims claims = Jwts.parser()
				.verifyWith(key)
				.requireIssuer(props.issuer())
				.build()
				.parseSignedClaims(token)
				.getPayload();
			return Optional.ofNullable(claims.getSubject());
		}
		catch (JwtException | IllegalArgumentException ex) {
			return Optional.empty();
		}
	}

	public long accessTokenTtlSeconds() {
		return props.accessTokenTtl().toSeconds();
	}

}
