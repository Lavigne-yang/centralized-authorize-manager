package com.inge.sso.authorize.server.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Map;

/**
 * @author lavyoung1325
 */
@Transient
public class ClientAuthenticationToken extends OAuth2ClientAuthenticationToken {


    public ClientAuthenticationToken(String clientId, ClientAuthenticationMethod clientAuthenticationMethod, @Nullable Object credentials, @org.springframework.lang.Nullable Map<String, Object> additionalParameters) {
        super(clientId, clientAuthenticationMethod, credentials, additionalParameters);
    }

    public ClientAuthenticationToken(RegisteredClient registeredClient, ClientAuthenticationMethod clientAuthenticationMethod, @Nullable Object credentials) {
        super(registeredClient, clientAuthenticationMethod, credentials);
    }
}
