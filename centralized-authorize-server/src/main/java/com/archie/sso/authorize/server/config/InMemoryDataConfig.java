package com.archie.sso.authorize.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * @author lavyoung1325
 */
@Configuration
public class InMemoryDataConfig {
    
    /**
     * 客户端Repository
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        //        RegisteredClient loginClient = RegisteredClient.withId(UUID.randomUUID().toString())
        //                .clientId("login-client")
        //                .clientSecret("{noop}openid-connect")
        //                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        //                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        //                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        //                .redirectUri("http://127.0.0.1:12000/login/oauth2/code/login-client")
        //                .redirectUri("http://127.0.0.1:12000/authorized")
        //                .scope(OidcScopes.OPENID)
        //                .scope(OidcScopes.PROFILE)
        //                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        //                .build();
        //        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        //                .clientId("CAM")
        //                .clientSecret("{noop}secret")
        //                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        //                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        //                .scope("cam:read")
        //                .scope("cam:write")
        //                .build();
        //        repository.save(loginClient);
        //        repository.save(registeredClient);
    }
    
    //    @Bean
    //    public UserDetailsService userDetailsService() {
    //        UserDetails user = User.builder()
    //                .username("user1")
    //                .password("$2a$10$.qdnTAO5.Oi4BTvTkc5j/e00M/yxBv63iXNXxtGSaFb8xi/vyOiYW")
    //                .roles("USER")
    //                .build();
    //        return new InMemoryUserDetailsManager(user);
    //    }
    
    /**
     * 添加认证服务器配置，设置jwt签发者、默认端点请求地址等
     *
     * @return
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                /**
                 * 设置token签发地址（http(s)://{ip},{domain}:{port}/context-path）
                 */.issuer("http://localhost:12000").build();
    }
    
}
