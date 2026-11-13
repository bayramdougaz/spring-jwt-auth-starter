package dev.bayram.auth.user;

import java.time.Instant;

/** Public view of a user. Never exposes the password hash. */
public record UserResponse(Long id, String email, String fullName, Role role, Instant createdAt) {

	public static UserResponse from(User user) {
		return new UserResponse(user.getId(), user.getEmail(), user.getFullName(), user.getRole(), user.getCreatedAt());
	}

}
