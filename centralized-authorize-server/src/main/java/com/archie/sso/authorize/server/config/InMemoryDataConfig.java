package com.archie.sso.authorize.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * @author lavyoung1325
 */
@Configuration
public class InMemoryDataConfig {
    
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
