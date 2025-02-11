package com.archie.sso.authorize.server.web;

import com.archie.sso.authorize.common.dto.User;
import com.archie.sso.authorize.common.exception.RegisterException;
import com.archie.sso.authorize.server.entity.UserEntity;
import com.archie.sso.authorize.server.service.UserService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 登录业务控制
 *
 * @author lavyoung1325
 */
@Controller
@RequiredArgsConstructor
public class LoginController {
    
    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);
    
    @NonNull
    private final UserService userService;
    
    @NonNull
    private final PasswordEncoder passwordEncoder;
    
    /**
     * 用户注册
     */
    @PostMapping("/user/register")
    public String userRegister(@RequestBody User user) {
        if (StringUtils.isEmpty(user.getAccount()) || StringUtils.isEmpty(user.getPassword())) {
            throw new RegisterException("账号或密码为空");
        }
        UserEntity userEntity = new UserEntity();
        BeanUtils.copyProperties(user, userEntity);
        String encode = passwordEncoder.encode(user.getPassword());
        if (StringUtils.isEmpty(user.getUsername())) {
            userEntity.setUsername(user.getAccount());
        }
        userEntity.setPassword(encode);
        userService.save(userEntity);
        return "/login";
    }
    
    @PostMapping("/user/login.action")
    public String login(@RequestParam("un") String username, @RequestParam("pw") String password, Model model) {
        // 输入验证
        if (username == null || username.trim().isEmpty() || password == null || password.trim().isEmpty()) {
            logger.warn("用户名或密码为空");
            model.addAttribute("error", "用户名或密码不能为空");
            return "/login";
        }
        try {
            UserDetails userDetails = userService.loadUserByUsername(username);
            if (userDetails == null) {
                logger.error("用户不存在");
                model.addAttribute("error", "用户不存在");
                return "/login";
            }
            
            if (!passwordEncoder.matches(password, userDetails.getPassword())) {
                logger.warn("密码不正确");
                model.addAttribute("error", "密码不正确");
                return "/login";
            }
            
            logger.info("用户登录成功: {}", userDetails.getUsername());
            return "/index";
        } catch (Exception e) {
            logger.error("登录过程中发生异常", e);
            model.addAttribute("error", "系统错误，请稍后再试");
            return "/login";
        }
    }
    
    
}
