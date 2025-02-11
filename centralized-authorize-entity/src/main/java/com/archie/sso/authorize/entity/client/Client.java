package com.archie.sso.authorize.entity.client;

import com.archie.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * @author lavyoung1325
 * @since 1.0.0
 */
@Data
public class Client implements Serializable {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    
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
