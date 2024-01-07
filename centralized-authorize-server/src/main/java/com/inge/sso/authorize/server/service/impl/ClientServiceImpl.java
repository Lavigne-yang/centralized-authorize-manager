package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.inge.sso.authorize.server.entity.ClientEntity;
import com.inge.sso.authorize.server.mapper.ClientMapper;
import com.inge.sso.authorize.server.service.ClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author lavyoung1325
 * @since 1.0.0
 */
@Service
public class ClientServiceImpl extends ServiceImpl<ClientMapper, ClientEntity> implements ClientService, RegisteredClientRepository {

    private static final Logger logger = LoggerFactory.getLogger(ClientServiceImpl.class);

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        logger.info("RegisteredClient save info: {}", registeredClient);
        RegisteredClient existingClient = findById(registeredClient.getId());
        if (existingClient != null) {
            this.baseMapper.updateById(dataToRow(registeredClient));
        } else {
            assertUniqueIdentifiers(registeredClient);
            this.baseMapper.insert(dataToRow(registeredClient));
        }
    }


    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        ClientEntity client = this.baseMapper.selectById(id);
        return rowToData(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        ClientEntity client = this.baseMapper.selectOne(Wrappers.lambdaQuery(ClientEntity.class)
                .eq(ClientEntity::getClientId, clientId));
        return rowToData(client);
    }


    private void assertUniqueIdentifiers(RegisteredClient registeredClient) {
        Long selectCount = this.baseMapper.selectCount(Wrappers.lambdaQuery(ClientEntity.class).eq(ClientEntity::getClientId, registeredClient.getClientId()));
        if (selectCount != 0 && selectCount > 0) {
            throw new IllegalArgumentException("Registered client must be unique. " +
                    "Found duplicate client identifier: " + registeredClient.getClientId());
        }
    }

    private RegisteredClient rowToData(ClientEntity clientEntity) {
        Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(clientEntity.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(clientEntity.getAuthorizationGrantTypes());
        Set<String> redirectUris = StringUtils.commaDelimitedListToSet(clientEntity.getRedirectUris());
        Set<String> clientScopes = StringUtils.commaDelimitedListToSet(clientEntity.getScopes());
        RegisteredClient.Builder builder = RegisteredClient.withId(clientEntity.getId())
                .clientId(clientEntity.getClientId())
                .clientIdIssuedAt(clientEntity.getClientIdIssuedAt())
                .clientSecret(clientEntity.getClientSecret())
                .clientSecretExpiresAt(clientEntity.getClientSecretExpiresAt())
                .clientName(clientEntity.getClientName())
                .clientAuthenticationMethods((authenticationMethods) ->
                        clientAuthenticationMethods.forEach(authenticationMethod ->
                                authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
                .authorizationGrantTypes((grantTypes) ->
                        authorizationGrantTypes.forEach(grantType ->
                                grantTypes.add(resolveAuthorizationGrantType(grantType))))
                .redirectUris((uris) -> uris.addAll(redirectUris))
                .scopes((scopes) -> scopes.addAll(clientScopes));
        Map<String, Object> clientSettingsMap = parseMap(clientEntity.getClientSettings());
        builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());
        Map<String, Object> tokenSettingsMap = parseMap(clientEntity.getTokenSettings());
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.withSettings(tokenSettingsMap);
        if (!tokenSettingsMap.containsKey(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT)) {
            tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
        }
        builder.tokenSettings(tokenSettingsBuilder.build());
        return builder.build();
    }

    private ClientEntity dataToRow(RegisteredClient registeredClient) {
        ClientEntity client = new ClientEntity();
        Instant issuedAt = registeredClient.getClientIdIssuedAt() != null ? registeredClient.getClientIdIssuedAt() : Instant.now();
        Instant secretExpiresAt = registeredClient.getClientSecretExpiresAt() != null ? registeredClient.getClientSecretExpiresAt() : Instant.now();
        List<String> clientAuthenticationMethods = registeredClient.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).collect(Collectors.toList());
        List<String> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());
        client.setId(registeredClient.getId());
        client.setClientId(registeredClient.getClientId());
        client.setClientIdIssuedAt(issuedAt);
        client.setClientSecret(registeredClient.getClientSecret());
        client.setClientSecretExpiresAt(secretExpiresAt);
        client.setClientName(registeredClient.getClientName());
        client.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
        client.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
        client.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        client.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
        client.setClientSettings(writeMap(registeredClient.getClientSettings().getSettings()));
        client.setTokenSettings(writeMap(registeredClient.getTokenSettings().getSettings()));
        return client;
    }

    private String writeMap(Map<String, Object> data) {
        try {
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }

    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }

    private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }
}
