package com.inge.sso.authorize.common.dto;

import lombok.Data;

import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 *
 * @author : lavyoung1325
 * @create 2023/9/24
 */
@Data
public class Client {

    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
//    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
//    private Set<AuthorizationGrantType> authorizationGrantTypes;
//    private Set<String> redirectUris;
//    private Set<String> scopes;
//    private ClientSettings clientSettings;
//    private TokenSettings tokenSettings;
}
