package com.inge.sso.authorize.server.config;

import com.inge.sso.authorize.server.authentication.DeviceClientAuthenticationProvider;
import com.inge.sso.authorize.server.authentication.converter.DeviceClientAuthenticationConverter;
import com.inge.sso.authorize.server.federation.FederatedIdentityIdTokenCustomizer;
import com.inge.sso.authorize.server.utils.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * 授权服务配置
 *
 * @author lavyoung1325
 */
@EnableWebSecurity
@Configuration
public class CamAuthorizationServerConfig {

    private JdbcTemplate jdbcTemplate;

    @Autowired
    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Spring security 的过滤器链，默认配置
     *
     *
     * @param httpSecurity
     * @param registeredClientRepository
     * @param authorizationServerSettings
     * @return
     * @throws Exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity, RegisteredClientRepository registeredClientRepository, AuthorizationServerSettings authorizationServerSettings) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter = new DeviceClientAuthenticationConverter(authorizationServerSettings.getAuthorizationEndpoint());
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider = new DeviceClientAuthenticationProvider(registeredClientRepository);
//        // httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).deviceAuthorizationEndpoint(deviceAuthorizationEndpoint -> deviceAuthorizationEndpoint.verificationUri("/")).deviceVerificationEndpoint(deviceVerificationEndpoint -> deviceVerificationEndpoint.consentPage("/error.html")).clientAuthentication(clientAuthentication -> clientAuthentication.authenticationConverter(deviceClientAuthenticationConverter).authenticationProvider(deviceClientAuthenticationProvider)).authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage("/error.html")).oidc(Customizer.withDefaults());
//        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
////                .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
////                        deviceAuthorizationEndpoint.verificationUri("/activate")
////                )
////                .deviceVerificationEndpoint(deviceVerificationEndpoint ->
////                        deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
////                )
//                .clientAuthentication(clientAuthentication ->
//                        clientAuthentication
//                                .authenticationConverter(deviceClientAuthenticationConverter)
//                                .authenticationProvider(deviceClientAuthenticationProvider)
//                )
//                .authorizationEndpoint(authorizationEndpoint ->
//                        authorizationEndpoint.consentPage("/error.html"))
//                .oidc(Customizer.withDefaults());
//        // Enable OpenID Connect 1.0
//        // @formatter:on
//
//        // @formatter:off
//        httpSecurity
//                .exceptionHandling((exception) -> exception
//                        .defaultAuthenticationEntryPointFor(
//                                new LoginUrlAuthenticationEntryPoint("/login"),
//                                new MediaTypeRequestMatcher(MediaType.ALL)
//                        )
//                )
//                .oauth2ResourceServer(oauth2ResourceServer ->
//                    oauth2ResourceServer.jwt(Customizer.withDefaults())
//                );
        // enable OpenID Connect 1.0
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication.authenticationConverter(deviceClientAuthenticationConverter)
                                .authenticationProvider(deviceClientAuthenticationProvider)
                        )
                .oidc(Customizer.withDefaults());
        httpSecurity.exceptionHandling(exceptions ->
                        // Redirect to the login page when not authenticated from the
                        // authorization endpoint
                        exceptions.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.ALL))
                )
                // ccept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return httpSecurity.build();
    }

    /**
     * 第三方授权客户端注册信息
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        return new FederatedIdentityIdTokenCustomizer();
    }

    /**
     * 用于给access_token签名使用
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return ((jwkSelector, securityContext) -> jwkSelector.select(jwkSet));
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationService() {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository());
    }

}
