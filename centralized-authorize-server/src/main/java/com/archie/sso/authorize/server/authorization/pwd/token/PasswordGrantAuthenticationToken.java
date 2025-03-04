package com.archie.sso.authorize.server.authorization.pwd.token;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.CollectionUtils;

import java.util.Map;
import java.util.Set;

/**
 * @author lvayoung1325
 */
@Getter
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    
    private final String username;
    
    private final String password;
    
    private final Set<String> scopes;
    
    
    public PasswordGrantAuthenticationToken(AuthorizationGrantType password, Authentication authentication,
            Set<String> requestScopes, Map<String, Object> parameters) {
        super(password, authentication, parameters);
        this.scopes = requestScopes;
        this.username = (String) parameters.get("username");
        this.password = (String) parameters.get("password");
        if (CollectionUtils.isEmpty(this.scopes)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
    }
    
    @Override
    public Object getCredentials() {
        return null;
    }
}
