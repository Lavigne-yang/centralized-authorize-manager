package com.inge.sso.authorize.server.web;

import com.inge.sso.authorize.common.dto.User;
import com.inge.sso.authorize.common.exception.RegisterException;
import com.inge.sso.authorize.server.entity.UserEntity;
import com.inge.sso.authorize.server.service.UserService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * 登录业务控制
 * @author lavyoung1325
 */
@Controller
public class LoginController {

    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    public LoginController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }


    @GetMapping("/register")
    public String register() {
        return "register";
    }

    /**
     * 用户注册
     *
     * @param user
     * @return
     */
    @PostMapping("/user/register")
    public String userRegister(@RequestBody User user) {
        if (StringUtils.isEmpty(user.getAccount()) || StringUtils.isEmpty(user.getPassword())) {
            throw new RegisterException("账号或密码为空");
        }
        UserEntity userEntity = new UserEntity();
        BeanUtils.copyProperties(user, userEntity);
        String encode = passwordEncoder.encode(user.getPassword());
        if (StringUtils.isEmpty(user.getNickName())) {
            userEntity.setNickName(user.getAccount());
        }
        userEntity.setPassword(encode);
        userService.save(userEntity);
        return "/login";
    }
}
