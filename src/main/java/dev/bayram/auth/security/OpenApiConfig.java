package dev.bayram.auth.security;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/** Adds an "Authorize" button to Swagger UI that sends the access token as a bearer header. */
@Configuration
@OpenAPIDefinition(info = @Info(title = "Spring JWT Auth Starter", version = "1.0",
		description = "Register, log in, refresh and protect endpoints with JWT."))
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT")
public class OpenApiConfig {
}
