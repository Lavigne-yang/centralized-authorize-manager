package com.archie.sso.authorize.server.controller;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.archie.sso.authorize.common.dto.Client;
import com.archie.sso.authorize.common.utils.ResultResponse;
import com.archie.sso.authorize.server.entity.ClientEntity;
import com.archie.sso.authorize.server.mapping.ClientMapping;

import lombok.RequiredArgsConstructor;

/**
 * @author lavyoung1325
 */
@RestController
@RequestMapping("/client")
@RequiredArgsConstructor
public class ClientController {

    private static final Logger logger = LoggerFactory.getLogger(ClientController.class);

    private final ClientMapping mapping;

    private final RegisteredClientRepository registeredClientRepository;

    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResultResponse<Boolean> register(@RequestBody Client client) {
        ClientEntity entity = mapping.toEntity(client);
        RegisteredClient build = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(entity.getClientId())
                // secret 由base65加密传输
                .clientSecret(passwordEncoder.encode(new String(Base64.getDecoder().decode(entity.getClientSecret()))))
                .clientName(entity.getClientName()).clientIdIssuedAt(Instant.now()).clientSecretExpiresAt(null)
                .postLogoutRedirectUri(entity.getPostLogoutRedirectUris())
                .authorizationGrantTypes(
                        authorizationGrantTypes -> StringUtils.commaDelimitedListToSet(
                                entity.getAuthorizationGrantTypes()).forEach(item -> {
                            authorizationGrantTypes.add(new AuthorizationGrantType(item));
                        }))
                .scopes(scopes -> {
                    scopes.addAll(StringUtils.commaDelimitedListToSet(entity.getScopes()));
                })
                .redirectUris(redirectUris -> {
                    redirectUris.addAll(StringUtils.commaDelimitedListToSet(entity.getRedirectUris()));
                })
                .clientAuthenticationMethods(clientAuthenticationMethods -> {
                    for (String string : StringUtils.commaDelimitedListToSet(entity.getClientAuthenticationMethods())) {
                        clientAuthenticationMethods.add(new ClientAuthenticationMethod(string));
                    }
                })
                .clientSettings(ClientSettings.builder().build())
                .tokenSettings(TokenSettings.builder().build())
                .build();
        registeredClientRepository.save(build);
        return new ResultResponse<Boolean>().success(true);
    }

}
