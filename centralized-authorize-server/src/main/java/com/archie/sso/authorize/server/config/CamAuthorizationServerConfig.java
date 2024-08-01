package com.archie.sso.authorize.server.config;

import com.archie.sso.authorize.common.constants.CamOauthConstants;
import com.archie.sso.authorize.server.pwd.provider.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import com.archie.sso.authorize.server.utils.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 授权服务配置
 *
 * @author lavyoung1325
 */
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class CamAuthorizationServerConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(CamAuthorizationServerConfig.class);
    
    private static final String CUSTOM_LOGIN_PAGE_URI = "/login";
    
    private final AuthenticationConfiguration authenticationConfiguration;
    
    /**
     * Spring security 的过滤器链，默认配置
     *
     * @param httpSecurity
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        //        httpSecurity.apply(authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenRequestConverter(
        //                new DelegatingAuthenticationConverter(Arrays.asList(
        //                        new OAuth2AuthorizationCodeAuthenticationConverter(),
        //                        new OAuth2RefreshTokenAuthenticationConverter(),
        //                        new OAuth2ClientCredentialsAuthenticationConverter(),
        //                        new OAuth2ResourceOwnerPasswordAuthenticationConverter()
        //                ))
        //        )));
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        //        httpSecurity.requestMatcher(endpointsMatcher)
        //                .authorizeRequests(authorization -> authorization.anyRequest().authenticated())
        //                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
        //                .apply(authorizationServerConfigurer);
        // 处理使用access token访问用户信息端点和客户端注册端点
        httpSecurity.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));
        authorizationServerConfigurer.oidc(oidc -> {
            oidc.userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper -> {
                OAuth2AccessToken accessToken = userInfoMapper.getAccessToken();
                Map<String, Object> claims = new HashMap<>();
                claims.put("url", "https://localhost/ITLab1024");
                claims.put("accessToken", accessToken);
                claims.put("sub", userInfoMapper.getAuthorization().getPrincipalName());
                return new OidcUserInfo(claims);
            }));
            // 客户端注册
            oidc.clientRegistrationEndpoint(Customizer.withDefaults());
        });
        DefaultSecurityFilterChain securityFilterChain = httpSecurity.formLogin(Customizer.withDefaults()).build();
        /*
             Custom configuration for Resource Owner Password grant type. Current implementation has no support for Resource Owner
         */
        //        addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(httpSecurity);
        return securityFilterChain;
    }
    
    
    @SuppressWarnings("unchecked")
    private void addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(HttpSecurity http) throws Exception {
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
        OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider = new OAuth2ResourceOwnerPasswordAuthenticationProvider(
                authenticationManager(authenticationConfiguration),
                http.getSharedObject(OAuth2AuthorizationService.class), tokenGenerator);
        // This will add new authentication provider in the list of existing authentication providers.
        http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);
    }
    
    
    /**
     * 基于db的oauth2的授权管理服务
     *
     * @return
     */
    @Bean
    @Order(Integer.MIN_VALUE)
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }
    
    /**
     * 自定义jwt，将权限信息放至jwt中
     *
     * @return
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        //        return new FederatedIdentityIdTokenCustomizer();
        return context -> {
            // 检查用户信息是不是UserDetails 排除没有用户参与的流程
            if (context.getPrincipal().getPrincipal() instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) context.getPrincipal().getPrincipal();
                // 获取申请的scopes
                Set<String> scopes = context.getAuthorizedScopes();
                // 获取用户的权限
                Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
                // 提取权限转为字符串
                Set<String> authoritySet = Optional.ofNullable(authorities).orElse(Collections.emptyList()).stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                // 合并scopes与用户信息
                authoritySet.addAll(scopes);
                JwtClaimsSet.Builder claims = context.getClaims();
                // 将权限信息放入jwt的claim中，也可以生产一个指定字符串分割的字符传放入
                claims.claim(CamOauthConstants.AUTHORIZATION_KEY, authoritySet);
                // 还可以继续放入其他信息
            }
        };
    }
    
    /**
     * 自定义jwt解析器，设置解析出来的权限信息的前缀与在jwt中的key
     *
     * @return jwt解析器 JwtAuthenticationConverter
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // 设置解析权限信息的前缀，设置为空是去掉前缀
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        // 设置权限信息在jwt， claim中的key
        grantedAuthoritiesConverter.setAuthoritiesClaimName(CamOauthConstants.AUTHORIZATION_KEY);
        
        JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
        authenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return authenticationConverter;
    }
    
    
    /**
     * 将AuthenticationManager注入ioc中，其它需要使用地方可以直接从ioc中获取
     *
     * @param authenticationConfiguration 导出认证配置
     * @return AuthenticationManager 认证管理器
     */
    @Bean
    @SneakyThrows
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    
    /**
     * jwk源，使用非对称加密，公开用于检索匹配指定选择器的JWK的方法
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }
    
    /**
     * 基于db的授权确认管理服务
     *
     * @return
     */
    // @Bean
    // public OAuth2AuthorizationConsentService oAuth2AuthorizationService() {
    //     return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository());
    // }
    
    /**
     * 密码解析器，使用BCrypt的方式对密码进行加密和验证
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
    
    /**
     * @return
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    
    /**
     * 配置jwt解析器
     *
     * @param jwkSource jwk源
     * @return
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
