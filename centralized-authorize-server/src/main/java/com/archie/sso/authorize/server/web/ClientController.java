//package com.archie.sso.authorize.server.web;
//
//import com.archie.sso.authorize.server.service.ClientService;
//import jakarta.annotation.Resource;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Qualifier;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.stereotype.Controller;
//import org.springframework.util.CollectionUtils;
//import org.springframework.util.StringUtils;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//
///**
// * @author lavyoung1325
// */
//@Controller("webClientControllerR")
//@RequestMapping("/client")
//public class ClientController {
//
//    private static final Logger logger = LoggerFactory.getLogger(ClientController.class);
//
//    @Resource
//    private ClientService clientService;
//
//    @Resource
//    private PasswordEncoder passwordEncoder;
//
//
//    @GetMapping("/activate")
//    public String activate(@RequestParam(value = "user_code", required = false) String userCode) {
//        if (userCode != null) {
//            return "redirect:/oauth2/device_verification?user_code=" + userCode;
//        }
//        return "device-activate";
//    }
//
//    @GetMapping("/activated")
//    public String activated() {
//        return "device-activated";
//    }
//
//    @GetMapping(value = "/", params = "success")
//    public String success() {
//        return "device-activated";
//    }
//
//
//    @PostMapping("/register")
//    public void registerClient(@RequestBody RegisteredClient client) {
//        logger.error("注册的客户端信息：{}", client);
//        if (!StringUtils.hasText(client.getClientId()) || !StringUtils.hasText(client.getClientSecret())
//                || !CollectionUtils.isEmpty(client.getScopes())) {
//            throw new IllegalArgumentException("缺少必要参数");
//        }
//    }
//}
