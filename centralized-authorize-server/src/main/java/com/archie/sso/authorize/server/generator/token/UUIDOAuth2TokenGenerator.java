package com.archie.sso.authorize.server.generator.token;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet.Builder;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-15
 */
public class UUIDOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {

    private final StringKeyGenerator accessTokenGenerator = new UUIDKeyGenerator();

    @Override
    public OAuth2AccessToken generate(OAuth2TokenContext context) {
        // 不透明token关闭 @formatter off
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) || !OAuth2TokenFormat.REFERENCE.equals(
                context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
            return null;
        }
        // 开启了不透明token
        String issuer = null;
        if (context.getAuthorizationServerContext() != null) {
            issuer = context.getAuthorizationServerContext().getIssuer();
        }
        RegisteredClient registeredClient = context.getRegisteredClient();
        Instant issuedAt = Instant.now();
        Instant expireAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

        Builder builder = OAuth2TokenClaimsSet.builder();
        if (StringUtils.hasText(issuer)) {
            builder.issuer(issuer);
        }
        builder
                .subject(context.getPrincipal().getName())
                .audience(Collections.singletonList(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expireAt)
                .notBefore(issuedAt)
                .id(UUID.randomUUID().toString());
        if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
            builder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
        }
        OAuth2TokenClaimsSet build = builder.build();
        return new OAuth2AccessTokenClaims(TokenType.BEARER, this.accessTokenGenerator.generateKey(),
                build.getIssuedAt(),
                build.getExpiresAt(), context.getAuthorizedScopes(), build.getClaims());
    }

    private static final class OAuth2AccessTokenClaims extends OAuth2AccessToken implements ClaimAccessor {
        private final Map<String, Object> claims;

        private OAuth2AccessTokenClaims(TokenType tokenType, String tokenValue,
                Instant issuedAt, Instant expiresAt, Set<String> scopes, Map<String, Object> claims) {
            super(tokenType, tokenValue, issuedAt, expiresAt, scopes);
            this.claims = claims;
        }

        @Override
        public Map<String, Object> getClaims() {
            return this.claims;
        }

    }
}
