package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.inge.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author lavyoung1325
 * @since 1.0.0
 */
@Data
@TableName("cam_oauth2_registered_client")
public class ClientEntity implements Serializable {

    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

    @TableId("id")
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private ClientSettings clientSettings;
    private TokenSettings tokenSettings;

    public static Builder withId(String id) {
        Assert.hasText(id, "id cannot be empty");
        return new Builder(id);
    }

    public static Builder from(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient);
    }

    @Data
    public static class Builder implements Serializable {

        private String id;
        private String clientId;
        private Instant clientIdIssuedAt;
        private String clientSecret;
        private Instant clientSecretExpiresAt;
        private String clientName;
        private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
        private Set<AuthorizationGrantType> authorizationGrantTypes;
        private Set<String> redirectUris;
        private Set<String> scopes;
        private ClientSettings clientSettings;
        private TokenSettings tokenSettings;
        private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

        protected Builder(String id) {
            this.id = id;
        }

        /**
         * 构造转换
         *
         * @param registeredClient 注册的客户端信息
         */
        protected Builder(RegisteredClient registeredClient) {
            this.id = registeredClient.getId();
            this.clientId = registeredClient.getClientId();
            this.clientIdIssuedAt = registeredClient.getClientIdIssuedAt();
            this.clientSecret = registeredClient.getClientSecret();
            this.clientSecretExpiresAt = registeredClient.getClientSecretExpiresAt();
            this.clientName = registeredClient.getClientName();
            if (!CollectionUtils.isEmpty(registeredClient.getClientAuthenticationMethods())) {
                this.clientAuthenticationMethods.addAll(registeredClient.getClientAuthenticationMethods());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getAuthorizationGrantTypes())) {
                this.authorizationGrantTypes.addAll(registeredClient.getAuthorizationGrantTypes());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getRedirectUris())) {
                this.redirectUris.addAll(registeredClient.getRedirectUris());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getScopes())) {
                this.scopes.addAll(registeredClient.getScopes());
            }
            this.clientSettings = ClientSettings.withSettings(registeredClient.getClientSettings().getSettings()).build();
            this.tokenSettings = TokenSettings.withSettings(registeredClient.getTokenSettings().getSettings()).build();
        }

        public ClientEntity build() {
            Assert.hasText(this.clientId, "clientId cannot be empty");
            Assert.notEmpty(this.authorizationGrantTypes, "authorizationGrantTypes cannot be empty");
            if (this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                Assert.notEmpty(this.redirectUris, "redirectUris cannot be empty");
            }
            if (!StringUtils.hasText(this.clientName)) {
                this.clientName = this.id;
            }
            if (CollectionUtils.isEmpty(this.clientAuthenticationMethods)) {
                this.clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            }
            if (this.clientSettings == null) {
                ClientSettings.Builder builder = ClientSettings.builder();
                if (isPublicClientType()) {
                    // @formatter:off
                    builder
                            .requireProofKey(true)
                            .requireAuthorizationConsent(true);
                    // @formatter:on
                }
                this.clientSettings = builder.build();
            }
            if (this.tokenSettings == null) {
                this.tokenSettings = TokenSettings.builder().build();
            }
            validateScopes();
            validateRedirectUris();
            return create();
        }

        private boolean isPublicClientType() {
            return this.authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE) &&
                    this.clientAuthenticationMethods.size() == 1 &&
                    this.clientAuthenticationMethods.contains(ClientAuthenticationMethod.NONE);
        }

        private ClientEntity create() {
            ClientEntity client = new ClientEntity();

            client.id = this.id;
            client.clientId = this.clientId;
            client.clientIdIssuedAt = this.clientIdIssuedAt;
            client.clientSecret = this.clientSecret;
            client.clientSecretExpiresAt = this.clientSecretExpiresAt;
            client.clientName = this.clientName;
            client.clientAuthenticationMethods = Collections.unmodifiableSet(
                    new HashSet<>(this.clientAuthenticationMethods));
            client.authorizationGrantTypes = Collections.unmodifiableSet(
                    new HashSet<>(this.authorizationGrantTypes));
            client.redirectUris = Collections.unmodifiableSet(
                    new HashSet<>(this.redirectUris));
            client.scopes = Collections.unmodifiableSet(
                    new HashSet<>(this.scopes));
            client.clientSettings = this.clientSettings;
            client.tokenSettings = this.tokenSettings;

            return client;
        }

        private void validateScopes() {
            if (CollectionUtils.isEmpty(this.scopes)) {
                return;
            }

            for (String scope : this.scopes) {
                Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
            }
        }

        private static boolean validateScope(String scope) {
            return scope == null ||
                    scope.chars().allMatch(c -> withinTheRangeOf(c, 0x21, 0x21) ||
                            withinTheRangeOf(c, 0x23, 0x5B) ||
                            withinTheRangeOf(c, 0x5D, 0x7E));
        }

        private static boolean withinTheRangeOf(int c, int min, int max) {
            return c >= min && c <= max;
        }

        private void validateRedirectUris() {
            if (CollectionUtils.isEmpty(this.redirectUris)) {
                return;
            }

            for (String redirectUri : redirectUris) {
                Assert.isTrue(validateRedirectUri(redirectUri),
                        "redirect_uri \"" + redirectUri + "\" is not a valid redirect URI or contains fragment");
            }
        }

        private static boolean validateRedirectUri(String redirectUri) {
            try {
                URI validRedirectUri = new URI(redirectUri);
                return validRedirectUri.getFragment() == null;
            } catch (URISyntaxException ex) {
                return false;
            }
        }
    }
}
