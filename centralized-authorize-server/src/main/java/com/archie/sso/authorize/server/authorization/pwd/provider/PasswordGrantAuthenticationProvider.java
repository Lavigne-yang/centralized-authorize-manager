package com.archie.sso.authorize.server.authorization.pwd.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
