package com.inge.sso.authorize.server.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 登录业务控制
 * @author lavyoung1325
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }


}
