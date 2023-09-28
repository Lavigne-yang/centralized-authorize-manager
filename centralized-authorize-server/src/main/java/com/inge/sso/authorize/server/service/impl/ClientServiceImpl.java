package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.ClientEntity;
import com.inge.sso.authorize.server.mapper.ClientMapper;
import com.inge.sso.authorize.server.service.IClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

/**
 * @author lavyoung1325
 * @since 1.0.0
 */
@Service
public class ClientServiceImpl extends ServiceImpl<ClientMapper, ClientEntity> implements IClientService, RegisteredClientRepository {

    private static final Logger logger = LoggerFactory.getLogger(ClientServiceImpl.class);

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        logger.info("RegisteredClient save info: {}", registeredClient);
        RegisteredClient existingClient = findById(registeredClient.getId());
        if (existingClient != null) {
            this.baseMapper.updateById(ClientEntity.fromUpdate(registeredClient).build());
        } else {
            assertUniqueIdentifiers(registeredClient);
            this.baseMapper.insert(ClientEntity.from(registeredClient).build());
        }
    }


    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        ClientEntity client = this.baseMapper.selectById(id);
        return getRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        ClientEntity client = this.baseMapper.selectOne(Wrappers.lambdaQuery(ClientEntity.class)
                .eq(ClientEntity::getClientId, clientId));
        return getRegisteredClient(client);
    }

    private RegisteredClient getRegisteredClient(ClientEntity client) {
        Assert.notNull(client, "client don't exist");
        logger.info("client info :{}", client);
        return RegisteredClient
                .withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(clientAuthenticationMethods -> {
                    clientAuthenticationMethods.addAll(client.getClientAuthenticationMethods());
                })
                .authorizationGrantTypes(authorizationGrantTypes -> {
                    authorizationGrantTypes.addAll(client.getAuthorizationGrantTypes());
                })
                .redirectUris(red -> {
                    red.addAll(client.getRedirectUris());
                })
                .scopes(sc -> {
                    sc.addAll(client.getScopes());
                })
                .clientSettings(client.getClientSettings())
                .tokenSettings(client.getTokenSettings())
                .build();
    }

    private void assertUniqueIdentifiers(RegisteredClient registeredClient) {
        Long selectCount = this.baseMapper.selectCount(Wrappers.lambdaQuery(ClientEntity.class).eq(ClientEntity::getClientId, registeredClient.getClientId()));
        if (selectCount != 0 && selectCount > 0) {
            throw new IllegalArgumentException("Registered client must be unique. " +
                    "Found duplicate client identifier: " + registeredClient.getClientId());
        }
    }
}
