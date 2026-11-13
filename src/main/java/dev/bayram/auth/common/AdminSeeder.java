package dev.bayram.auth.common;

import dev.bayram.auth.user.Role;
import dev.bayram.auth.user.User;
import dev.bayram.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Creates the first admin account on startup so the admin endpoints are usable right away. */
@Configuration
public class AdminSeeder {

	private static final Logger log = LoggerFactory.getLogger(AdminSeeder.class);

	@Bean
	ApplicationRunner seedAdmin(UserRepository users, PasswordEncoder encoder,
			@Value("${app.admin.email}") String email, @Value("${app.admin.password}") String password) {
		return args -> {
			if (!users.existsByEmailIgnoreCase(email)) {
				users.save(new User(email.toLowerCase(), encoder.encode(password), "Administrator", Role.ADMIN));
				log.info("Created admin account {}", email);
			}
		};
	}

}
