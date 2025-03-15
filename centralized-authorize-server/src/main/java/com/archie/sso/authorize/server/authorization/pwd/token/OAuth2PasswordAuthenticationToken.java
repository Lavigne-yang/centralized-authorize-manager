package com.archie.sso.authorize.server.authorization.pwd.token;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import lombok.Getter;

/**
 * @author lvayoung1325
 */
@Getter
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;

    private final String password;

    public OAuth2PasswordAuthenticationToken(String username, String password, Authentication authentication,
            Map<String, Object> parameters) {
        super(AuthorizationGrantType.PASSWORD, authentication, parameters);
        this.username = username;
        this.password = password;
    }


}
