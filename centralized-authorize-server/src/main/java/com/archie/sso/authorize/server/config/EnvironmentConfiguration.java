package com.archie.sso.authorize.server.config;

import org.apache.rocketmq.spring.support.DefaultRocketMQListenerContainer;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;


/**
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-16
 */
@Configuration
public class EnvironmentConfiguration implements BeanPostProcessor {

    @Value("${rocketmq.enhance.enabledIsolation:true}")
    private boolean enabledIsolation;
    @Value("${rocketmq.enhance.environment:''}")
    private String environmentName;


    /**
     * 装载bean时可以做对应的修改
     */
    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        // 可以在bean初始化前做需要的适配
        if (bean instanceof DefaultRocketMQListenerContainer container) {
            //拼接Topic
            if (enabledIsolation && StringUtils.hasText(environmentName)) {
                container.setTopic(String.join("_", container.getTopic(), environmentName));
            }
            return container;
        }
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        // 可以在bean初始化完成后做一些其他的事情
        return BeanPostProcessor.super.postProcessAfterInitialization(bean, beanName);
    }
}
