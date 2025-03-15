package com.archie.sso.authorize.server.authorization.pwd.provider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext.Builder;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import com.archie.sso.authorize.server.authorization.pwd.token.OAuth2PasswordAuthenticationToken;
import com.archie.sso.authorize.server.service.AuthorizationService;
import com.archie.sso.authorize.server.service.UserService;

/**
 * @author lavyoung1325
 */
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {

    private final AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    private String username = null, password = null;
    private Set<String> authorizedScopes = new HashSet<>();

    public OAuth2PasswordAuthenticationProvider(AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, UserService userService,
            PasswordEncoder passwordEncoder) {
        Assert.notNull(authorizationService, "authorizationService must not be null");
        Assert.notNull(tokenGenerator, "tokenGenerator must not be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2PasswordAuthenticationToken passwordAuthentication = (OAuth2PasswordAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal =
                OAuth2PasswordAuthenticationProvider.getAuthenticatedClientElseThrowInvalidClient(
                        passwordAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        username = passwordAuthentication.getUsername();
        password = passwordAuthentication.getPassword();
        Assert.notNull(username, "username must not be null");
        Assert.notNull(password, "password must not be null");

        // 验证用户名密码
        UserDetails userDetails = userService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }
        if (CollectionUtils.isEmpty(registeredClient.getAuthorizationGrantTypes())
                || !registeredClient.getAuthorizationGrantTypes().contains(passwordAuthentication.getGrantType())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        authorizedScopes.forEach(scope -> {
            if (!registeredClient.getAuthorizationGrantTypes().contains(scope)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
        });

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        // 生成access_token
        Builder tokenBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthenticationToken)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(passwordAuthentication.getGrantType())
                .authorizationGrant(passwordAuthentication)
                .authorizedScopes(authorizedScopes);
        // access_token
        DefaultOAuth2TokenContext tokenContext = tokenBuilder.build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        // not null
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", null);
            throw new OAuth2AuthenticationException(error);
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(TokenType.BEARER, generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), authorizedScopes);
        // Initialize the OAuth2Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .authorizationGrantType(passwordAuthentication.getGrantType());

        if (generatedAccessToken instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken, meta -> {
                meta.put(Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
            });
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // refresh token
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
                && !clientPrincipal.getClientAuthenticationMethod().equals(
                ClientAuthenticationMethod.NONE)) {
            tokenContext = tokenBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token auth2Token = this.tokenGenerator.generate(tokenContext);
            if (!(auth2Token instanceof OAuth2RefreshToken auth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generate failed to generate the refresh token", null);
                throw new OAuth2AuthenticationException(error);
            }
            authorizationBuilder.refreshToken(auth2RefreshToken);
        }

        // ID-token
        //        OidcIdToken oidcIdToken;
        //        if (authorizedScopes.contains(OidcScopes.OPENID)) {
        //            SessionInformation sessionInformation = getSessionInformation
        //            (usernamePasswordAuthenticationToken);
        //            if (sessionInformation != null) {
        //                try {
        //                    SessionInformation information = new SessionInformation(sessionInformation.getPrincipal(),
        //                            createHash(sessionInformation.getSessionId()), sessionInformation
        //                            .getLastRequest());
        //                } catch (NoSuchAlgorithmException e) {
        //                    OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
        //                            "Failed to compute hash for Session ID.", null);
        //                    throw new OAuth2AuthenticationException(error);
        //                }
        //                tokenBuilder.put(SessionInformation.class, sessionInformation);
        //            }
        //            //
        //            tokenContext = tokenBuilder.tokenType(ID_TOKEN_TYPE)
        //                    .authorization(authorizationBuilder.build())
        //                    .build();
        //
        //            // on
        //            OAuth2Token generateToken = this.tokenGenerator.generate(tokenContext);
        //            if (!(generateToken instanceof Jwt jwt)) {
        //                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
        //                        "The token generator failed to generate the ID token.", null);
        //                throw new OAuth2AuthenticationException(error);
        //            }
        //            oidcIdToken = new OidcIdToken(generateToken.getTokenValue(), generateToken.getIssuedAt(),
        //                    generateToken.getExpiresAt(), jwt.getClaims());
        //            authorizationBuilder.token(oidcIdToken, meta -> {
        //                meta.put(Token.CLAIMS_METADATA_NAME, oidcIdToken.getClaims());
        //            });
        //
        //        } else {
        //            oidcIdToken = null;
        //        }
        //        Map<String, Object> additionalParameters = Collections.emptyMap();
        //        if (oidcIdToken != null) {
        //            additionalParameters = new HashMap<>();
        //            additionalParameters.put(OidcParameterNames.ID_TOKEN, oidcIdToken.getTokenValue());
        //        }
        //
        //        OAuth2Authorization.Builder authorization =
        //                authorizationBuilder.attribute(Principal.class.getName(),
        //                usernamePasswordAuthenticationToken);
        // 保存授权信息
        this.authorizationService.save(authorizationBuilder.build());
        //        Map<String, Object> additionalParameters = new HashMap<>(){{
        //            put(OAuth2ParameterNames.USERNAME, username);
        //        }};
        // 返回
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken,
                Collections.emptyMap());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
            Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    //    private SessionInformation getSessionInformation(Authentication principal) {
    //        SessionInformation sessionInformation = null;
    //        if (this.sessionRegistry != null) {
    //            List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal.getPrincipal(),
    //            false);
    //            if (!CollectionUtils.isEmpty(sessions)) {
    //                sessionInformation = sessions.getFirst();
    //                if (sessions.size() > 1) {
    //                    sessions = new ArrayList<>(sessions);
    //                    sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
    //                    sessionInformation = sessions.getLast();
    //                }
    //            }
    //        }
    //        return sessionInformation;
    //    }

    /**
     * 将给定的字符串值转换为SHA-256哈希值，并以Base64编码的形式返回 此方法用于生成给定文本的唯一标识符，常用于数据校验和加密场景
     *
     * @param value 需要转换为哈希值的原始字符串
     * @return 返回经过SHA-256哈希处理并使用Base64编码的字符串
     * @throws NoSuchAlgorithmException 如果Java安全API不支持SHA-256算法，则抛出此异常
     */
    private static String createHash(String value) throws NoSuchAlgorithmException {
        // 获取SHA-256算法的消息摘要实例
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // 使用ASCII字符集将输入字符串转换为字节数组，然后计算哈希值
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        // 使用Base64对哈希值进行编码，选择URL安全的编码方式并去除填充字符
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
