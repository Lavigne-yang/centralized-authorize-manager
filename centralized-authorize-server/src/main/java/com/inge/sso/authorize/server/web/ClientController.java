package com.inge.sso.authorize.server.web;

import com.inge.sso.authorize.server.service.IClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

/**
 * @author lavyoung1325
 */
@Controller
@RequestMapping("/client")
public class ClientController {

    private static final Logger logger = LoggerFactory.getLogger(ClientController.class);

    private final IClientService clientService;

    private final PasswordEncoder passwordEncoder;

    public ClientController(IClientService clientService, PasswordEncoder passwordEncoder) {
        this.clientService = clientService;
        this.passwordEncoder = passwordEncoder;
    }


    @GetMapping("/activate")
    public String activate(@RequestParam(value = "user_code", required = false) String userCode) {
        if (userCode != null) {
            return "redirect:/oauth2/device_verification?user_code=" + userCode;
        }
        return "device-activate";
    }

    @GetMapping("/activated")
    public String activated() {
        return "device-activated";
    }

    @GetMapping(value = "/", params = "success")
    public String success() {
        return "device-activated";
    }


    @PostMapping("/register")
    public void registerClient(@RequestBody RegisteredClient client) {
        logger.error("注册的客户端信息：{}", client);
        if (!StringUtils.hasText(client.getClientId()) || !StringUtils.hasText(client.getClientSecret()) || !CollectionUtils.isEmpty(client.getScopes())) {
            throw new IllegalArgumentException("缺少必要参数");
        }
//        RegisteredClient built = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId(client.getClientId())
//                .clientSecret(passwordEncoder.encode(client.getClientSecret()))
//                .clientAuthenticationMethods(client.getClientAuthenticationMethods())
//                .authorizationGrantTypes(client.getAuthorizationGrantTypes())
//                .scopes(client.getScopes())
//                .redirectUris(client.getRedirectUris())
//                .build();
//        registeredClientRepository.save(built);
    }
}
