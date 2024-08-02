package com.archie.sso.authorize.common.dto;

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
    
    private String clientAuthenticationMethods;
    
    private String authorizationGrantTypes;
    
    private String redirectUris;
    
    private String postLogoutRedirectUris;
    
    private String scopes;
    
    private String clientSettings;
    
    private String tokenSettings;
}
