package dev.bayram.auth.user;

import java.util.List;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
@Tag(name = "Users")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

	private final UserRepository users;

	public UserController(UserRepository users) {
		this.users = users;
	}

	@GetMapping("/users/me")
	@Operation(summary = "Current user's profile")
	public UserResponse me(@AuthenticationPrincipal User user) {
		return UserResponse.from(user);
	}

	@GetMapping("/admin/users")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "List all users (admin only)")
	public List<UserResponse> listUsers() {
		return users.findAll().stream().map(UserResponse::from).toList();
	}

	public record ChangeRoleRequest(@NotNull Role role) {
	}

	@PatchMapping("/admin/users/{id}/role")
	@PreAuthorize("hasRole('ADMIN')")
	@Operation(summary = "Change a user's role (admin only)")
	public UserResponse changeRole(@PathVariable Long id, @Valid @RequestBody ChangeRoleRequest request) {
		User user = users.findById(id)
			.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
		user.setRole(request.role());
		return UserResponse.from(users.save(user));
	}

}
