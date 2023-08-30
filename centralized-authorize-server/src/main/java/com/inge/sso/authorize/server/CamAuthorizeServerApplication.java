package com.inge.sso.authorize.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * @author lavyoung1325
 */
@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class CamAuthorizeServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(CamAuthorizeServerApplication.class);
    }
}
