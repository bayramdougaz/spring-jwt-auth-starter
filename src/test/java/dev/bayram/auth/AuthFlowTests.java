package dev.bayram.auth;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowTests {

	@Autowired
	MockMvc mvc;

	@Test
	void registerThenAccessProtectedEndpoint() throws Exception {
		String body = register("alice@example.com", "Password1", "Alice")
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.tokenType").value("Bearer"))
			.andExpect(jsonPath("$.user.role").value("USER"))
			.andReturn().getResponse().getContentAsString();

		mvc.perform(get("/api/users/me").header("Authorization", "Bearer " + JsonPath.read(body, "$.accessToken")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.email").value("alice@example.com"))
			.andExpect(jsonPath("$.password").doesNotExist());
	}

	@Test
	void protectedEndpointRequiresToken() throws Exception {
		mvc.perform(get("/api/users/me")).andExpect(status().isUnauthorized());
		mvc.perform(get("/api/users/me").header("Authorization", "Bearer not-a-jwt"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void duplicateEmailIsRejected() throws Exception {
		register("bob@example.com", "Password1", "Bob").andExpect(status().isCreated());
		register("BOB@example.com", "Password1", "Bob again").andExpect(status().isConflict());
	}

	@Test
	void weakPasswordFailsValidation() throws Exception {
		register("carol@example.com", "short", "Carol")
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.errors.password").exists());
	}

	@Test
	void wrongPasswordReturns401() throws Exception {
		register("dave@example.com", "Password1", "Dave");
		login("dave@example.com", "WrongPass1").andExpect(status().isUnauthorized());
	}

	@Test
	void refreshTokenIsRotatedAndReuseRevokesSession() throws Exception {
		String first = register("erin@example.com", "Password1", "Erin").andReturn().getResponse().getContentAsString();
		String oldRefresh = JsonPath.read(first, "$.refreshToken");

		String second = refresh(oldRefresh).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		String newRefresh = JsonPath.read(second, "$.refreshToken");

		// Reusing the old token fails, and also revokes the newer one.
		refresh(oldRefresh).andExpect(status().isUnauthorized());
		refresh(newRefresh).andExpect(status().isUnauthorized());
	}

	@Test
	void logoutRevokesRefreshToken() throws Exception {
		String body = register("frank@example.com", "Password1", "Frank").andReturn().getResponse().getContentAsString();
		String refreshToken = JsonPath.read(body, "$.refreshToken");

		mvc.perform(post("/api/auth/logout").contentType(MediaType.APPLICATION_JSON)
			.content("{\"refreshToken\":\"" + refreshToken + "\"}")).andExpect(status().isNoContent());
		refresh(refreshToken).andExpect(status().isUnauthorized());
	}

	@Test
	void adminEndpointsAreRoleProtected() throws Exception {
		String user = register("gina@example.com", "Password1", "Gina").andReturn().getResponse().getContentAsString();
		mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + JsonPath.read(user, "$.accessToken")))
			.andExpect(status().isForbidden());

		String admin = login("admin@example.com", "Admin123!").andExpect(status().isOk())
			.andReturn().getResponse().getContentAsString();
		mvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + JsonPath.read(admin, "$.accessToken")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[*].email", hasItem("gina@example.com")));
	}

	@Test
	void docsAndHealthArePublic() throws Exception {
		mvc.perform(get("/v3/api-docs")).andExpect(status().isOk())
			.andExpect(jsonPath("$.paths['/api/auth/login']").exists());
		mvc.perform(get("/actuator/health")).andExpect(status().isOk())
			.andExpect(jsonPath("$.status").value("UP"));
	}

	private ResultActions register(String email, String password, String name) throws Exception {
		return mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"email":"%s","password":"%s","fullName":"%s"}""".formatted(email, password, name)));
	}

	private ResultActions login(String email, String password) throws Exception {
		return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
			.content("""
					{"email":"%s","password":"%s"}""".formatted(email, password)));
	}

	private ResultActions refresh(String token) throws Exception {
		return mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON)
			.content("{\"refreshToken\":\"" + token + "\"}"));
	}

}
