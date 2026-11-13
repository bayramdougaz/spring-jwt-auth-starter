package dev.bayram.auth.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import dev.bayram.auth.auth.AuthDtos.AuthResponse;
import dev.bayram.auth.auth.AuthDtos.LoginRequest;
import dev.bayram.auth.auth.AuthDtos.RegisterRequest;
import dev.bayram.auth.security.JwtProperties;
import dev.bayram.auth.security.JwtService;
import dev.bayram.auth.user.Role;
import dev.bayram.auth.user.User;
import dev.bayram.auth.user.UserRepository;
import dev.bayram.auth.user.UserResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {

	private static final SecureRandom RANDOM = new SecureRandom();

	private final UserRepository users;

	private final RefreshTokenRepository refreshTokens;

	private final PasswordEncoder passwordEncoder;

	private final AuthenticationManager authenticationManager;

	private final JwtService jwtService;

	private final JwtProperties jwtProperties;

	public AuthService(UserRepository users, RefreshTokenRepository refreshTokens, PasswordEncoder passwordEncoder,
			AuthenticationManager authenticationManager, JwtService jwtService, JwtProperties jwtProperties) {
		this.users = users;
		this.refreshTokens = refreshTokens;
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
		this.jwtProperties = jwtProperties;
	}

	@Transactional
	public AuthResponse register(RegisterRequest request) {
		if (users.existsByEmailIgnoreCase(request.email())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
		}
		User user = users.save(new User(request.email().toLowerCase(), passwordEncoder.encode(request.password()),
				request.fullName().trim(), Role.USER));
		return issueTokens(user);
	}

	@Transactional
	public AuthResponse login(LoginRequest request) {
		// Throws BadCredentialsException on a wrong email or password (mapped to 401).
		var auth = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.email(), request.password()));
		return issueTokens((User) auth.getPrincipal());
	}

	/**
	 * Exchanges a valid refresh token for a new token pair. The old refresh token is revoked
	 * (rotation). If a revoked token is presented again it was probably stolen, so every
	 * session of that user is revoked.
	 */
	@Transactional(noRollbackFor = ResponseStatusException.class)
	public AuthResponse refresh(String rawRefreshToken) {
		RefreshToken stored = refreshTokens.findByTokenHash(hash(rawRefreshToken))
			.orElseThrow(AuthService::invalidRefreshToken);
		if (!stored.isActive()) {
			refreshTokens.revokeAllForUser(stored.getUser(), Instant.now());
			throw invalidRefreshToken();
		}
		stored.revoke();
		return issueTokens(stored.getUser());
	}

	@Transactional
	public void logout(String rawRefreshToken) {
		refreshTokens.findByTokenHash(hash(rawRefreshToken)).ifPresent(RefreshToken::revoke);
	}

	private AuthResponse issueTokens(User user) {
		String rawRefresh = newOpaqueToken();
		refreshTokens.save(new RefreshToken(hash(rawRefresh), user,
				Instant.now().plus(jwtProperties.refreshTokenTtl())));
		return new AuthResponse(jwtService.generateAccessToken(user), rawRefresh, "Bearer",
				jwtService.accessTokenTtlSeconds(), UserResponse.from(user));
	}

	private static String newOpaqueToken() {
		byte[] bytes = new byte[48];
		RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static String hash(String value) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static ResponseStatusException invalidRefreshToken() {
		return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
	}

}
