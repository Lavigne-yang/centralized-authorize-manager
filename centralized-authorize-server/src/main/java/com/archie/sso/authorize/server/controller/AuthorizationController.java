package com.archie.sso.authorize.server.controller;

import com.archie.sso.authorize.common.exception.BusinessException;
import com.archie.sso.authorize.server.service.ClientService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

/**
 * 授权管理
 *
 * @author lavyoung1325
 */
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class AuthorizationController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationController.class);
    
    private final PasswordEncoder passwordEncoder;
    
    private final RegisteredClientRepository registeredClientRepository;
    
    private final ClientService clientService;
    
    /**
     * 请求授权
     *
     * @param clientId     客户端ID
     * @param clientSecret 客户端secret
     * @param responseType 响应方式
     * @param redirectUrl  重定向url
     * @param response     响应
     */
    @GetMapping("/authorize")
    public void authorize(@RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret, @RequestParam("response_type") String responseType,
            @RequestParam("redirect_url") String redirectUrl, HttpServletResponse response) {
        try {
            // 1.客户端应用配置校验
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                throw new BusinessException("客户端应用不存在");
            }
            boolean matches = passwordEncoder.matches(passwordEncoder.encode(clientSecret),
                    registeredClient.getClientSecret());
            if (!matches) {
                throw new BusinessException("客户端应用密钥错误");
            }
            Set<AuthorizationGrantType> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes();
            if (!authorizationGrantTypes.contains(new AuthorizationGrantType(responseType))) {
                throw new BusinessException("授权方式不支持");
            }
            if (!registeredClient.getRedirectUris().contains(redirectUrl)) {
                throw new BusinessException("重定向url错误");
            }
            // 2. 生成授权码 todo
            
            response.sendRedirect("");
        } catch (Exception e) {
            logger.error("请求授权错误：", e);
            throw new BusinessException("500");
        }
    }
}
