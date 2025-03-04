package com.archie.sso.authorize.server.authorization.pwd.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;
import java.util.Set;

/**
 * @author lvayoung1325
 */
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    
    private final String username;
    
    private final String password;
    
    private final Set<String> requestScopes;
    
    
    public PasswordGrantAuthenticationToken(AuthorizationGrantType password, Authentication authentication,
            Set<String> requestScopes, Map<String, Object> parameters) {
        // TODO Auto-generated method stub
        super(password, authentication, parameters);
        this.username = (String) parameters.get("username");
        this.password = (String) parameters.get("password");
        this.requestScopes = requestScopes;
    }
    
    public Set<String> getRequestScopes() {
        return requestScopes;
    }
}
