package com.archie.sso.authorize.common.dto;

import java.time.Instant;
import java.util.List;

import lombok.Data;

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
    private List<String> clientAuthenticationMethods;
    private List<String> authorizationGrantTypes;
    private List<String> redirectUris;
    private List<String> postLogoutRedirectUris;
    private List<String> scopes;
    private List<String> clientSettings;
    private List<String> tokenSettings;
}
