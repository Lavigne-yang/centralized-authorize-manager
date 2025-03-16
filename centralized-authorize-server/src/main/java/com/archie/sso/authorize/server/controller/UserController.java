package com.archie.sso.authorize.server.controller;


import org.apache.rocketmq.client.producer.SendCallback;
import org.apache.rocketmq.client.producer.SendResult;
import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.archie.sso.authorize.entity.user.User;
import com.archie.sso.authorize.server.entity.UserEntity;
import com.archie.sso.authorize.server.service.UserService;

import cn.hutool.json.JSONUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * @author lavyoung1325
 */
@RestController
@RequestMapping("/u")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    
    private final UserService userService;
    private final RedisTemplate redisTemplate;
    @Value("${rocketmq.topic}")
    private String topic;
    private final RocketMQTemplate rocketMTemplate;


    @PostMapping(value = "/register", consumes = "application/json", produces = "application/json")
    public ResponseEntity<Object> register(@RequestBody User user) {

        // 普通发送
        // rocketMTemplate.convertAndSend(topic + ":user" , user);
        rocketMTemplate.convertAndSend(topic + ":user", MessageBuilder.withPayload(user).build());

        return ResponseEntity.ok(Boolean.TRUE);
    }

    @PostMapping("/register1")
    public ResponseEntity<Object> register1(@RequestBody User user) {

        // 普通发送
        rocketMTemplate.convertAndSend(topic + ":user", user);

        return ResponseEntity.ok(Boolean.TRUE);
    }

    /**
     * 发送同步消息（阻塞当前线程，等待broker响应发送结果，这样不太容易丢失消息）
     * （msgBody也可以是对象，sendResult为返回的发送结果）
     */
    @PostMapping("/register2")
    public ResponseEntity<Object> register2(@RequestBody User user) {

        SendResult sendResult = rocketMTemplate.syncSend(topic + ":user", MessageBuilder.withPayload(user).build());
        log.info("发送结果：{}", JSONUtil.toJsonStr(sendResult));
        return ResponseEntity.ok(JSONUtil.toJsonStr(sendResult));
    }

    /**
     * 发送异步消息（通过线程池执行发送到broker的消息任务，执行完后回调：在SendCallback中可处理相关成功失败时的逻辑）
     * （适合对响应时间敏感的业务场景）
     */
    @PostMapping("/register3")
    public ResponseEntity<Object> register3(@RequestBody User user) {

        rocketMTemplate.asyncSend(topic + ":user", user, new SendCallback() {
            @Override
            public void onSuccess(SendResult sendResult) {
                log.info("发送结果：{}", JSONUtil.toJsonStr(sendResult));
            }

            @Override
            public void onException(Throwable throwable) {
                log.error("发送失败：{}", throwable.getMessage());
                throwable.printStackTrace();
            }
        });
        return ResponseEntity.ok(Boolean.TRUE);
    }


    /**
     * 发送延时消息（上面的发送同步消息，delayLevel的值就为0，因为不延时）
     * 在start版本中 延时消息一共分为18个等级分别为：1s 5s 10s 30s 1m 2m 3m 4m 5m 6m 7m 8m 9m 10m 20m 30m 1h 2h
     */
    @PostMapping("/register4")
    public ResponseEntity<Object> register4(@RequestBody User user,
            @RequestParam(value = "delayLevel") int delayLevel) {

        rocketMTemplate.syncSend(topic + ":user", user, delayLevel);
        return ResponseEntity.ok(Boolean.TRUE);
    }


    /**
     * 发送单向消息（只负责发送消息，不等待应答，不关心发送结果，如日志）
     */
    @PostMapping("/register5")
    public ResponseEntity<Object> register5(@RequestBody User user) {

        rocketMTemplate.sendOneWay(topic + ":user", user);
        return ResponseEntity.ok(Boolean.TRUE);
    }


    /**
     * 发送带tag的消息，直接在topic后面加上":tag"
     */
    @PostMapping("/register6")
    public ResponseEntity<Object> register6(@RequestBody User user) {

        rocketMTemplate.syncSend(topic + ":user:tag1", user);
        return ResponseEntity.ok(Boolean.TRUE);
    }


    @GetMapping("/info")
    public ResponseEntity<Object> info(@RequestParam("id") String id) {
        Object object = redisTemplate.opsForValue().get("user:info:" + id);
        if (object != null) {
            return ResponseEntity.ok(object);
        }
        UserEntity user = userService.getById(id);
        if (id == null) {
            return ResponseEntity.ok(user);
        }
        redisTemplate.opsForValue().set("user:info:" + id, user);
        return ResponseEntity.ok(user);
    }


}
