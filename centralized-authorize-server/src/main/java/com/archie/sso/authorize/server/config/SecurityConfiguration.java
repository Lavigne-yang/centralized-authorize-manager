package com.archie.sso.authorize.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.archie.sso.authorize.server.authorization.pwd.converter.OAuth2PasswordAuthenticationConverter;
import com.archie.sso.authorize.server.authorization.pwd.provider.OAuth2PasswordAuthenticationProvider;
import com.archie.sso.authorize.server.federation.ReferenceTokenEnhancer;
import com.archie.sso.authorize.server.federation.SelfContainedTokenEnhancer;
import com.archie.sso.authorize.server.generator.token.UUIDOAuth2RefreshTokenGenerator;
import com.archie.sso.authorize.server.generator.token.UUIDOAuth2TokenGenerator;
import com.archie.sso.authorize.server.service.AuthorizationService;
import com.archie.sso.authorize.server.service.UserService;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    @NonNull
    private final JwtEncoder jwtEncoder;
    @NonNull
    private final SelfContainedTokenEnhancer selfContainedTokenEnhancer;
    @NonNull
    private final ReferenceTokenEnhancer referenceTokenEnhancer;
    @NonNull
    private final AuthorizationService authorityService;
    @NonNull
    private final UserService userService;
    @NonNull
    private final PasswordEncoder passwordEncoder;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .with(authorizationServerConfigurer,
                        authorizationServer -> authorizationServer.tokenEndpoint(tokenEndpoint ->
                                tokenEndpoint.accessTokenRequestConverter(new OAuth2PasswordAuthenticationConverter())
                                        .authenticationProvider(
                                                new OAuth2PasswordAuthenticationProvider(authorityService,
                                                        tokenGenerator(), userService, passwordEncoder))
                        )
                )
        ;
        http
                // 暂时
                .csrf(AbstractHttpConfigurer::disable)
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }


    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        // 当客户端的tokenSetting的OAuth2TokenFormat设置为OAuth2TokenFormat.SELF_CONTAINED时 使用下面的
        // jwtToken生成器（当客户端的token格式为self-contained时使用）
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        // 设置jwt-token自定义扩展
        //        jwtGenerator.setJwtCustomizer(selfContainedTokenEnhancer);
        //
        //        // 当客户端的tokenSetting的OAuth2TokenFormat设置为OAuth2TokenFormat.REFERENCE 使用下面的
        //        // 不透明的token生成器
        //        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        //        // 设置id-token自定义扩展
        //        accessTokenGenerator.setAccessTokenCustomizer(referenceTokenEnhancer);
        //
        //        // refreshToken生成器
        //        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        UUIDOAuth2RefreshTokenGenerator uuidoAuth2RefreshTokenGenerator = new UUIDOAuth2RefreshTokenGenerator();
        UUIDOAuth2TokenGenerator accessTokenGenerator = new UUIDOAuth2TokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, uuidoAuth2RefreshTokenGenerator);
    }

}
