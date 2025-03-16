package com.archie.sso.authorize.server.config.redis;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.connection.RedisClusterConfiguration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisNode;
import org.springframework.data.redis.connection.RedisSentinelConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration.LettucePoolingClientConfigurationBuilder;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

import com.archie.sso.authorize.server.config.redis.serializer.StringKeySerializer;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.lettuce.core.ClientOptions;
import io.lettuce.core.ReadFrom;
import io.lettuce.core.cluster.ClusterClientOptions;
import io.lettuce.core.cluster.ClusterTopologyRefreshOptions;
import io.lettuce.core.resource.DefaultClientResources;
import jakarta.annotation.Resource;

/**
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-15
 */
@Configuration
@Import(value = {CustomRedisProperties.class})
public class RedisConfiguration {

    @Resource
    private CustomRedisProperties customRedisProperties;
    @Resource
    private RedisProperties redisProperties;

    private GenericObjectPoolConfig<?> genericObjectPoolConfig(RedisProperties.Pool properties) {
        GenericObjectPoolConfig<?> config = new GenericObjectPoolConfig<>();
        config.setMaxTotal(properties.getMaxActive());
        config.setMaxIdle(properties.getMaxIdle());
        config.setMinIdle(properties.getMinIdle());
        config.setTestOnCreate(true);
        config.setTimeBetweenEvictionRuns(properties.getTimeBetweenEvictionRuns());
        config.setMaxWait(properties.getMaxWait());
        return config;
    }

    private LettucePoolingClientConfiguration poolingClientConfiguration() {
        DefaultClientResources clientResources = DefaultClientResources.create();
        //开启 自适应集群拓扑刷新和周期拓扑刷新
        ClusterTopologyRefreshOptions clusterTopologyRefreshOptions = ClusterTopologyRefreshOptions.builder()
                // 开启全部自适应刷新 自适应刷新不开启,Redis集群变更时将会导致连接异常
                .enableAllAdaptiveRefreshTriggers()
                // 自适应刷新超时时间(默认30秒)
                //默认关闭开启后时间为30秒
                .adaptiveRefreshTriggersTimeout(Duration.ofSeconds(15))
                // 开周期刷新
                // 默认关闭开启后时间为60秒 ClusterTopologyRefreshOptions.DEFAULT_REFRESH_PERIOD 60  .enablePeriodicRefresh
                // (Duration.ofSeconds(2)) = .enablePeriodicRefresh().refreshPeriod(Duration.ofSeconds(2))
                .enablePeriodicRefresh(Duration.ofSeconds(15))
                .build();

        ClientOptions clientOptions = ClusterClientOptions.builder()
                .topologyRefreshOptions(clusterTopologyRefreshOptions)
                .build();
        LettucePoolingClientConfigurationBuilder builder = LettucePoolingClientConfiguration.builder();
        return builder.clientName(redisProperties.getClientName())
                .clientResources(clientResources)
                .poolConfig(genericObjectPoolConfig(redisProperties.getLettuce().getPool()))
                .commandTimeout(Duration.ofSeconds(redisProperties.getTimeout().getSeconds()))
                .shutdownTimeout(Duration.ofSeconds(redisProperties.getLettuce().getShutdownTimeout().getSeconds()))
                .clientOptions(clientOptions)
                .readFrom(ReadFrom.MASTER_PREFERRED)
                .build();
    }


    /**
     * 单例模式
     *
     * @return redis连接工厂
     */
    @ConditionalOnProperty(value = "spring.data.redis.mode", havingValue = "standalone")
    @Bean
    public RedisConnectionFactory standaloneConnectionFactory() {
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
        redisStandaloneConfiguration.setDatabase(redisProperties.getDatabase());
        redisStandaloneConfiguration.setHostName(redisProperties.getHost());
        redisStandaloneConfiguration.setPort(redisProperties.getPort());
        redisStandaloneConfiguration.setUsername(redisProperties.getUsername());
        redisStandaloneConfiguration.setPassword(redisProperties.getPassword());
        LettuceConnectionFactory connectionFactory =
                new LettuceConnectionFactory(redisStandaloneConfiguration, poolingClientConfiguration());
        connectionFactory.setValidateConnection(true);
        connectionFactory.afterPropertiesSet();
        return connectionFactory;
    }

    /**
     * 集群模式
     *
     * @return redis连接工厂
     */
    @ConditionalOnProperty(value = "spring.data.redis.mode", havingValue = "cluster")
    @Bean
    public RedisConnectionFactory clusterConnectionFactory() {
        RedisClusterConfiguration clusterConfiguration = new RedisClusterConfiguration();
        LettuceConnectionFactory factory =
                new LettuceConnectionFactory(clusterConfiguration, poolingClientConfiguration());
        clusterConfiguration.setUsername(redisProperties.getUsername());
        clusterConfiguration.setPassword(redisProperties.getPassword());
        clusterConfiguration.setMaxRedirects(redisProperties.getCluster().getMaxRedirects());
        List<RedisNode> redisNodes = new ArrayList<>();
        for (String node : redisProperties.getCluster().getNodes()) {
            redisNodes.add(RedisNode.fromString(node));
        }
        clusterConfiguration.setClusterNodes(redisNodes);
        factory.setValidateConnection(true);
        factory.afterPropertiesSet();
        return factory;
    }

    /**
     * sentinel模式
     *
     * @return redis连接工厂
     */
    @ConditionalOnProperty(value = "spring.data.redis.mode", havingValue = "sentinel")
    @Bean
    public RedisConnectionFactory lettuceConnectionFactory() {
        RedisSentinelConfiguration redisSentinelConfiguration = new RedisSentinelConfiguration();
        redisSentinelConfiguration.setDatabase(redisProperties.getDatabase());
        redisSentinelConfiguration.setUsername(redisProperties.getUsername());
        redisSentinelConfiguration.setPassword(redisProperties.getPassword());
        redisSentinelConfiguration.setMaster(redisProperties.getSentinel().getMaster());
        redisSentinelConfiguration.setSentinelUsername(redisProperties.getSentinel().getUsername());
        redisSentinelConfiguration.setSentinelPassword(redisProperties.getSentinel().getUsername());
        for (String node : redisProperties.getSentinel().getNodes()) {
            redisSentinelConfiguration.addSentinel(RedisNode.fromString(node));
        }
        return new LettuceConnectionFactory(redisSentinelConfiguration, poolingClientConfiguration());
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(new StringKeySerializer(customRedisProperties.getKeyPrefix()));
        redisTemplate.setValueSerializer(jackson2JsonRedisSerializer());
        return redisTemplate;
    }

    private Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer() {
        ObjectMapper objectMapper = new ObjectMapper();
        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer =
                new Jackson2JsonRedisSerializer<>(objectMapper, Object.class);
        objectMapper.setVisibility(PropertyAccessor.ALL, Visibility.ANY);
        ClassLoader classLoader = RedisConfiguration.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        objectMapper.registerModules(securityModules);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        return jackson2JsonRedisSerializer;
    }

}
