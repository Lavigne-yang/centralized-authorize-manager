package com.archie.sso.authorize.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import com.archie.sso.authorize.server.generator.token.CustomAuthorizationCodeGenerator;

import lombok.RequiredArgsConstructor;

/**
 * @author lavyoung1325
 */
@Configuration
@RequiredArgsConstructor
public class InMemoryDataConfig {

    private final JwtEncoder jwtEncoder;

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator() {
        // 设备码, 用户码生成暂时不做
        return new DelegatingOAuth2TokenGenerator(new JwtGenerator(jwtEncoder)
                , new OAuth2AccessTokenGenerator(), new CustomAuthorizationCodeGenerator(),
                new OAuth2RefreshTokenGenerator());
    }
    
}
