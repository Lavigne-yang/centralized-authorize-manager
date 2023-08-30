package com.inge.sso.authorize.server.config;

import com.inge.sso.authorize.server.authentication.DeviceClientAuthenticationProvider;
import com.inge.sso.authorize.server.authentication.converter.DeviceClientAuthenticationConverter;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.UUID;

/**
 * 授权服务配置
 *
 * @author lavyoung1325
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class CamAuthorizationServerConfig {


    @Autowired
    private ServerProperties serverProperties;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity, RegisteredClientRepository registeredClientRepository, AuthorizationServerSettings authorizationServerSettings) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter = new DeviceClientAuthenticationConverter(authorizationServerSettings.getAuthorizationEndpoint());
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider = new DeviceClientAuthenticationProvider(registeredClientRepository);
        // httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).deviceAuthorizationEndpoint(deviceAuthorizationEndpoint -> deviceAuthorizationEndpoint.verificationUri("/")).deviceVerificationEndpoint(deviceVerificationEndpoint -> deviceVerificationEndpoint.consentPage("/error.html")).clientAuthentication(clientAuthentication -> clientAuthentication.authenticationConverter(deviceClientAuthenticationConverter).authenticationProvider(deviceClientAuthenticationProvider)).authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage("/error.html")).oidc(Customizer.withDefaults());
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
//                        deviceAuthorizationEndpoint.verificationUri("/activate")
//                )
//                .deviceVerificationEndpoint(deviceVerificationEndpoint ->
//                        deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
//                )
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                .authenticationConverter(deviceClientAuthenticationConverter)
                                .authenticationProvider(deviceClientAuthenticationProvider)
                )
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.consentPage("/error.html"))
                .oidc(Customizer.withDefaults());
        // Enable OpenID Connect 1.0
        // @formatter:on

        // @formatter:off
        httpSecurity
                .exceptionHandling((exception) -> exception
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.ALL)
                        )
                )
                .oauth2ResourceServer(oauth2ResourceServer ->
                    oauth2ResourceServer.jwt(Customizer.withDefaults())
                );
        return httpSecurity.build();
    }


    /**
     * 加载系统注册信息
     * @param jdbcTemplate
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("cam")
                .clientSecret("camsecret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("")
                .redirectUri("")
//                .postLogoutRedirectUri("")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        jdbcRegisteredClientRepository.save(registeredClient);

        return jdbcRegisteredClientRepository;
    }


    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {

        return null;
    }

}
