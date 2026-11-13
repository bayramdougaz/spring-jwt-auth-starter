package dev.bayram.auth.security;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed binding for the {@code app.jwt.*} properties.
 *
 * @param secret base64-encoded HMAC key, at least 256 bits
 * @param accessTokenTtl lifetime of a signed access token
 * @param refreshTokenTtl lifetime of an opaque refresh token
 * @param issuer value of the {@code iss} claim
 */
@ConfigurationProperties("app.jwt")
public record JwtProperties(String secret, Duration accessTokenTtl, Duration refreshTokenTtl, String issuer) {
}
