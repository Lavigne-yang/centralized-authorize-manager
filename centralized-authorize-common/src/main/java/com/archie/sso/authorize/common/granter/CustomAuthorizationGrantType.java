package com.archie.sso.authorize.common.granter;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-15
 */
public record CustomAuthorizationGrantType(String value) {

    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");
}
