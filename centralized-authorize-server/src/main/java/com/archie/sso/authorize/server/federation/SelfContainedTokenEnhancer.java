package com.archie.sso.authorize.server.federation;

import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * 透明token拓展
 *
 * @author lavyoung1325
 */
@Component
public class SelfContainedTokenEnhancer implements OAuth2TokenCustomizer<JwtEncodingContext> {


    @Override
    public void customize(JwtEncodingContext context) {
        context.getClaims().claims(claim -> {
            claim.put("tokenType--1", context.getTokenType());
            claim.put("self", true);
            claim.put("name", context.getPrincipal().getName());
        });
    }
}
