package com.inge.sso.authorize.server.authorization.pwd.provider;


import com.inge.sso.authorize.server.authorization.pwd.OAuth2ResourceOwnerPasswordAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author lavyoung1325
 */
public class OAuth2ResourceOwnerPasswordAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2ResourceOwnerPasswordAuthenticationProvider.class);

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    /**
     * Constructs an {@code OAuth2ResourceOwnerPasswordAuthenticationProviderNew} using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     * @param authorizationService  the authorization service
     * @param tokenGenerator        the token generator
     * @since 1.0.0
     */
    public OAuth2ResourceOwnerPasswordAuthenticationProvider(AuthenticationManager authenticationManager, OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ResourceOwnerPasswordAuthenticationToken resouceOwnerPasswordAuthentication = (OAuth2ResourceOwnerPasswordAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(resouceOwnerPasswordAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (logger.isTraceEnabled()) {
            logger.trace("Retrieved registered client");
        }
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        Authentication passwordAuthentication = getUsernamePasswordAuthentication(resouceOwnerPasswordAuthentication);
        Set<String> registeredClientScopes = registeredClient.getScopes();
        Set<String> requestedScopes = resouceOwnerPasswordAuthentication.getScopes();
        if (!CollectionUtils.isEmpty(requestedScopes)) {
            Set<String> collected = requestedScopes.stream().filter(s -> !registeredClient.getScopes().contains(s)).collect(Collectors.toSet());
            if (!CollectionUtils.isEmpty(collected)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
            registeredClientScopes = new LinkedHashSet<>(requestedScopes);
        }
        if (logger.isTraceEnabled()) {
            logger.trace("Validated token request parameters");
        }
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder().registeredClient(registeredClient)
                .principal(passwordAuthentication)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(registeredClientScopes)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(resouceOwnerPasswordAuthentication);

        DefaultOAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generated = this.tokenGenerator.generate(tokenContext);
        if (generated == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }
        if (logger.isTraceEnabled()) {
            logger.trace("Generated access token");
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generated.getTokenValue(), generated.getIssuedAt(), generated.getExpiresAt(), tokenContext.getAuthorizedScopes());

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(passwordAuthentication.getName())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizedScopes(registeredClientScopes)
                .attribute(Principal.class.getName(), passwordAuthentication);
        if (generated instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generated).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        OAuth2RefreshToken auth2RefreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }
            if (logger.isTraceEnabled()) {
                logger.trace("Generated refresh token");
            }
            auth2RefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(auth2RefreshToken);
        }

        OidcIdToken idToken;
        if (requestedScopes.contains(OidcScopes.OPENID)) {
            tokenContext = tokenContextBuilder.tokenType(ID_TOKEN_TOKEN_TYPE)
                    .authorization(authorizationBuilder.build())
                    .build();
            OAuth2Token generateToken = this.tokenGenerator.generate(tokenContext);
            if (!(generateToken instanceof Jwt)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the ID token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }
            if (logger.isTraceEnabled()) {
                logger.trace("Generated id token");
            }
            idToken = new OidcIdToken(generateToken.getTokenValue(), generated.getIssuedAt(), generateToken.getExpiresAt(), ((Jwt) generateToken).getClaims());
            authorizationBuilder.token(idToken, metadata -> {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims());
            });
        } else {
            idToken = null;
        }
        OAuth2Authorization authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);

        if (logger.isTraceEnabled()) {
            logger.trace("Saved authorization");
        }
        Map<String, Object> additionalParameters = new HashMap<>();
        if (idToken != null) {
            additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
        }
        if (logger.isTraceEnabled()) {
            logger.trace("Authenticated token request");
        }
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, auth2RefreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        boolean supports = OAuth2ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
        logger.debug("supports authentication=" + authentication + " returning " + supports);
        return supports;
    }

    private Authentication getUsernamePasswordAuthentication(OAuth2ResourceOwnerPasswordAuthenticationToken resouceOwnerPasswordAuthentication) {
        Map<String, Object> additionalParameters = resouceOwnerPasswordAuthentication.getAdditionalParameters();
        String username = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
        String password = (String) additionalParameters.get(OAuth2ParameterNames.PASSWORD);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        logger.debug("got usernamePasswordAuthenticationToken=" + usernamePasswordAuthenticationToken);
        Authentication usernamePasswordAuthentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        return usernamePasswordAuthentication;
    }


    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {

        OAuth2ClientAuthenticationToken clientPrincipal = null;

        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
