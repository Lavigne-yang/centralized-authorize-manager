package com.inge.sso.authorize.server.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;


/**
 * 设备授权
 *
 * @author lavyoung1325
 */
public class ClientAuthenticationProvider implements AuthenticationProvider {

    private final Logger logger = LoggerFactory.getLogger(ClientAuthenticationProvider.class);

    private final RegisteredClientRepository registeredClientRepository;

    public ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ClientAuthenticationToken deviceClientAuthentication = (ClientAuthenticationToken) authentication;
        if (!ClientAuthenticationMethod.NONE.equals(deviceClientAuthentication.getClientAuthenticationMethod())) {
            // 授权方式
            return null;
        }
        String clientId = deviceClientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            // 该客户端无授权
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }
        if (!this.logger.isDebugEnabled()) {
            // 检查是否注册该客户端
            this.logger.debug("Retrieved registered client");
        }
        if (!registeredClient.getClientAuthenticationMethods().contains(deviceClientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method not found");
        }
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Validated device client authentication parameters");
        }
        if (this.logger.isInfoEnabled()) {
            this.logger.info("Authenticated device client: {}", registeredClient.getClientId());
        }
        // 返回token
        return new ClientAuthenticationToken(registeredClient, deviceClientAuthentication.getClientAuthenticationMethod(), null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * 无效客户端
     *
     * @param parameterName
     */
    private static void throwInvalidClient(String parameterName) {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Device client authentication failed: " + parameterName,
                "error_uri"
        );
        throw new OAuth2AuthenticationException(error);
    }
}
