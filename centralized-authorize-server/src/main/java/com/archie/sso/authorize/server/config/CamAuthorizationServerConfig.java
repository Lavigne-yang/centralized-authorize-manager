package com.archie.sso.authorize.server.config;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings.Builder;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.archie.sso.authorize.common.constants.CamOauthConstants;
import com.archie.sso.authorize.server.pwd.provider.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import com.archie.sso.authorize.server.service.AuthorizationConsentService;
import com.archie.sso.authorize.server.service.AuthorizationService;
import com.archie.sso.authorize.server.service.ClientService;

import lombok.RequiredArgsConstructor;

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

    private final AuthenticationManager authenticationManager;

    private final AuthorizationService authorizationService;

    private final ClientService clientService;

    private final AuthorizationConsentService authorizationConsentService;

    private final OAuth2TokenGenerator<OAuth2Token> auth2TokenGenerator;

    /**
     * Spring security 的过滤器链
     */
    @Bean
    @Order(1)
    @Primary
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        logger.info("加载http security模块");
        applyCustomSecurity(httpSecurity);

        // 启用OpenID
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        httpSecurity.httpBasic(Customizer.withDefaults());
        // 未经授权重定向至登录页面
        httpSecurity.exceptionHandling(ex -> {
            ex.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint(CUSTOM_LOGIN_PAGE_URI),
                    new MediaTypeRequestMatcher(MediaType.ALL));
        }).oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(httpSecurity, authorizationService,
                authenticationManager);
        logger.info("加载http security模块成功");
        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        logger.info("加载默认http security模块");
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        logger.info("加载默认http security模块");
        return http.build();
    }


    public void applyCustomSecurity(HttpSecurity http) throws Exception {
        // 注册配置
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        authorizationServerConfigurer.setBuilder(http);
        authorizationServerConfigurer.authorizationService(authorizationService);
        authorizationServerConfigurer.registeredClientRepository(clientService);
        authorizationServerConfigurer.authorizationConsentService(authorizationConsentService);
        authorizationServerConfigurer.tokenGenerator(auth2TokenGenerator);
        authorizationServerConfigurer.authorizationServerSettings(authorizationServerSettings());

        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();
        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                .csrf((csrf) -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .with(authorizationServerConfigurer, Customizer.withDefaults());

    }

    @SuppressWarnings("unchecked")
    private void addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(HttpSecurity http,
            AuthorizationService authorizationService, AuthenticationManager authenticationManager) {
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
        OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider =
                new OAuth2ResourceOwnerPasswordAuthenticationProvider(
                        authenticationManager,
                        authorizationService, tokenGenerator);
        // This will add new authentication provider in the list of existing authentication providers.
        http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);
    }


    /**
     * 授权配置地址
     * {"settings.authorization-server.oidc-client-registration-endpoint":"/connect/register","settings
     * .authorization-server.authorization-endpoint":"/oauth2/authorize","settings.authorization-server
     * .token-endpoint":"/oauth2/token","settings.authorization-server.oidc-logout-endpoint":"/connect/logout",
     * "settings.authorization-server.device-verification-endpoint":"/oauth2/device_verification","settings
     * .authorization-server.issuer":"http://localhost:12000","settings.authorization-server
     * .multiple-issuers-allowed":false,"settings.authorization-server
     * .device-authorization-endpoint":"/oauth2/device_authorization","settings.authorization-server
     * .jwk-set-endpoint":"/oauth2/jwks","settings.authorization-server.token-revocation-endpoint":"/oauth2/revoke",
     * "settings.authorization-server.oidc-user-info-endpoint":"/userinfo","settings.authorization-server
     * .token-introspection-endpoint":"/oauth2/introspect"}
     */
    public AuthorizationServerSettings authorizationServerSettings() {
        Builder builder = AuthorizationServerSettings.builder()
                .authorizationEndpoint("/oauth2/authorize1")
                .issuer("http://localhost:12000");
        return builder.build();
    }

    /**
     * 自定义jwt，将权限信息放至jwt中
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        //        return new FederatedIdentityIdTokenCustomizer();
        return context -> {
            // 检查用户信息是不是UserDetails 排除没有用户参与的流程
            if (context.getPrincipal().getPrincipal() instanceof UserDetails userDetails) {
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
     //* @param authenticationConfiguration 导出认证配置
     * @return AuthenticationManager 认证管理器
     */
    //    @Bean
    //    @SneakyThrows
    //    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
    //            throws Exception {
    //        return authenticationConfiguration.getAuthenticationManager();
    //    }




}
