package com.archie.sso.authorize.server.federation;

import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * 透明token拓展
 *
 * @author lavyoung1325
 */
@Component
public class ReferenceTokenEnhancer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        //        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
        //            Map<String, Object> thirdPartyClaims = extractClaims(context.getPrincipal());
        //            context.getClaims().claims(existingClaims -> {
        //                // Remove conflicting claims set by this authorization server
        //                existingClaims.keySet().forEach(thirdPartyClaims::remove);
        //
        //                // Remove standard id_token claims that could cause problems with clients
        //                ID_TOKEN_CLAIMS.forEach(thirdPartyClaims::remove);
        //
        //                // Add all other claims directly to id_token
        //                existingClaims.putAll(thirdPartyClaims);
        //            });
        //        }
        context.getClaims().claims(claim -> {
            claim.put("tokenType--1", context.getTokenType());
            claim.put("self", false);
            claim.put("name", context.getPrincipal().getName());
        });
    }


}
