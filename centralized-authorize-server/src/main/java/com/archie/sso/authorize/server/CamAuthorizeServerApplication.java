package com.archie.sso.authorize.server;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author lavyoung1325
 */
@SpringBootApplication
@MapperScan("com.archie.sso.authorize.server.mapper")
public class CamAuthorizeServerApplication extends SpringApplication {
    
    public static void main(String[] args) {
        System.setProperty("rocketmq.client.logUseSlf4j", "true");
        run(CamAuthorizeServerApplication.class, args);
    }


}
