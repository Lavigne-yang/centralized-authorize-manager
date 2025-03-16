package com.archie.sso.authorize.server.config.redis;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-15
 */
@ConfigurationProperties(prefix = "spring.data.redis.custom")
@Data
public class CustomRedisProperties {

    private String keyPrefix;
}
