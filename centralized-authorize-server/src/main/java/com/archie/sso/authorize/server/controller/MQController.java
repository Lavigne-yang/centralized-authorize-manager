package com.archie.sso.authorize.server.controller;

import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.Resource;

/**
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-16
 */
@RestController("/mq")
public class MQController {

    @Value("${rocketmq.topic}")
    private String topic;

    @Resource
    private RocketMQTemplate rocketMTemplate;

    @PostMapping("/addd")
    public void aa() {
        rocketMTemplate.convertAndSend(topic, "hello");
    }

    @GetMapping("/aa")
    public void ab() {
        rocketMTemplate.convertAndSend(topic, "hello");
    }
}
