package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.ClientEntity;
import com.inge.sso.authorize.server.mapper.ClientMapper;
import com.inge.sso.authorize.server.service.IClientService;
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
    @Override
    public void save(RegisteredClient registeredClient) {
        this.baseMapper.insert(ClientEntity.from(registeredClient).build());
    }

    @Override
    public RegisteredClient findById(String id) {
        ClientEntity client = this.baseMapper.selectById(id);
        return getRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        ClientEntity client = this.baseMapper.selectOne(Wrappers.lambdaQuery(ClientEntity.class)
                .eq(ClientEntity::getClientId, clientId));
        return getRegisteredClient(client);
    }

    private RegisteredClient getRegisteredClient(ClientEntity client) {
        Assert.notNull(client, "client don't exist");
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
}
