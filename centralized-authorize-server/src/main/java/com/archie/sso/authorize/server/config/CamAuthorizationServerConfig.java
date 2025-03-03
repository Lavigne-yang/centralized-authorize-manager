package com.archie.sso.authorize.server.config;

import com.archie.sso.authorize.common.constants.CamOauthConstants;
import com.archie.sso.authorize.server.handler.UserLoginFailureHandler;
import com.archie.sso.authorize.server.handler.UserLoginSuccessHandler;
import com.archie.sso.authorize.server.pwd.provider.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import com.archie.sso.authorize.server.service.AuthorizationConsentService;
import com.archie.sso.authorize.server.service.AuthorizationService;
import com.archie.sso.authorize.server.service.ClientService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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

import java.util.Collection;
import java.util.Collections;
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
    
    @NonNull
    private final AuthenticationConfiguration authenticationConfiguration;
    
    @NonNull
    private final AuthenticationManager authenticationManager;
    
    @NonNull
    private final AuthorizationService authorizationService;
    
    @NonNull
    private final ClientService clientService;
    
    @NonNull
    private final AuthorizationConsentService authorizationConsentService;
    
    @NonNull
    private final OAuth2TokenGenerator<OAuth2Token> auth2TokenGenerator;
    
    @NonNull
    private final UserLoginSuccessHandler userLoginSuccessHandler;
    
    @NonNull
    private final UserLoginFailureHandler userLoginFailureHandler;

    /**
     * Spring security 的过滤器链
     * 该方法配置了Web安全属性，包括HTTP基本认证、OAuth2授权服务器配置、资源服务器配置等
     * 主要目的是为了保护Web应用程序免受各种攻击，如跨站请求伪造（CSRF）、点击劫持等
     * 同时，它也配置了自定义的安全属性，如自定义登录页面、OpenID支持等
     *
     * @param httpSecurity 用于配置Web安全属性的HttpSecurity对象
     * @return 配置好的SecurityFilterChain对象
     * @throws Exception 配置过程中可能抛出的异常
     */
    @Bean
    @Order(1)
    @Primary
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // 记录日志，开始加载http security模块
        logger.info("加载http security模块");
        // 应用自定义的安全配置
        applyCustomSecurity(httpSecurity);
        
        // 启用OpenID
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        // 配置HTTP基本认证
        httpSecurity.httpBasic(Customizer.withDefaults());
        // 未经授权重定向至登录页面
        httpSecurity.exceptionHandling(ex -> {
            ex.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint(CUSTOM_LOGIN_PAGE_URI),
                    new MediaTypeRequestMatcher(MediaType.ALL));
        }).oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        // 添加自定义的OAuth2资源所有者密码认证提供者
        //        addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(httpSecurity, authorizationService,
        //                authenticationManager);
        // 记录日志，成功加载http security模块
        logger.info("加载http security模块成功");
        // 构建并返回配置好的SecurityFilterChain对象
        return httpSecurity.build();
    }
    
    /**
     * 配置默认的安全过滤链
     *
     * 此方法用于配置Spring Security中的HttpSecurity，以定义Web应用程序的安全约束
     * 它指定了哪些URL路径需要保护，哪些不需要，以及如何处理登录和注销
     *
     * @param http 用于配置Web安全的HttpSecurity对象
     * @return 配置好的SecurityFilterChain对象
     * @throws Exception 如果配置过程中发生错误
     */
    //    @Bean
    //    @Order(2)
    //    @ConditionalOnMissingBean(SecurityFilterChain.class)
    //    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    //        // 开始加载默认的HTTP Security配置
    //        logger.info("加载默认http security模块");
    //
    //        // 配置授权请求
    //        http.authorizeHttpRequests((authorize) ->
    //                        authorize.requestMatchers("/login","/error").permitAll()
    //                                .anyRequest().authenticated())
    //                // 配置表单登录
    //                .formLogin(form ->
    //                        form.loginPage("/login")
    //                                .loginProcessingUrl("/login")
    //                                .defaultSuccessUrl("/index", true)
    //                ).logout(Customizer.withDefaults())
    //                // 禁用CSRF保护，以便简化示例
    //                .csrf(AbstractHttpConfigurer::disable);
    //
    //        // 完成加载默认的HTTP Security配置
    //        logger.info("加载默认http security模块");
    //
    //        // 构建并返回配置好的SecurityFilterChain
    //        return http.build();
    //    }
    
    
    /**
     * 应用自定义安全设置到HttpSecurity 此方法配置了OAuth2授权服务器的必要组件，如授权服务、客户端仓库、授权同意服务、令牌生成器等 它还定义了哪些请求匹配器需要应用这些安全设置，并设置了CSRF保护的忽略匹配器
     *
     * @param http HttpSecurity实例，用于配置Web安全
     * @throws Exception 配置过程中可能抛出的异常
     */
    private void applyCustomSecurity(HttpSecurity http) throws Exception {
        // 注册配置
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        authorizationServerConfigurer.setBuilder(http);
        authorizationServerConfigurer.authorizationService(authorizationService);
        authorizationServerConfigurer.registeredClientRepository(clientService);
        authorizationServerConfigurer.authorizationConsentService(authorizationConsentService);
        authorizationServerConfigurer.tokenGenerator(auth2TokenGenerator);
        
        authorizationServerConfigurer.authorizationServerSettings(authorizationServerSettings());
    
        // 获取端点匹配器
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();
    
        // 配置HttpSecurity
        http
                // 确保所有端点都要求身份验证
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests((authorize) -> authorize.requestMatchers("/login", "/error").permitAll()
                        .anyRequest().authenticated())
                // 配置表单登录
                .formLogin(form -> form.loginProcessingUrl("/login.action").successHandler(userLoginSuccessHandler)
                        .failureHandler(userLoginFailureHandler).defaultSuccessUrl("/index", false))
                .logout(Customizer.withDefaults())
                // 禁用CSRF保护，以便简化示例
                .csrf(AbstractHttpConfigurer::disable)
                // 应用OAuth2授权服务器配置器
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
     * 配置授权服务器的设置
     *
     * 此方法定义了授权服务器的相关端点和配置信息，包括：
     * - 客户端注册端点
     * - 授权端点
     * - 令牌端点
     * - 登录注销端点
     * - 设备验证端点
     * - 发行者URL
     * - 是否允许多个发行者
     * - 设备授权端点
     * - JWK集合端点
     * - 令牌撤销端点
     * - 用户信息端点
     * - 令牌检查端点
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
     * @return AuthorizationServerSettings对象，包含了授权服务器的配置信息
     */
    public AuthorizationServerSettings authorizationServerSettings() {
        Builder builder = AuthorizationServerSettings.builder().authorizationEndpoint("/oauth2/authorize1")
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


}
