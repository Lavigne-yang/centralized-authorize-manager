package com.archie.sso.authorize.server.authorization.pwd.provider;

import com.archie.sso.authorize.server.authorization.pwd.token.PasswordGrantAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.util.CollectionUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;

/**
 * @author lavyoung1325
 */
public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {
    
    private SessionRegistry sessionRegistry;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
    
    private static OAuth2ClientAuthenticationToken extractOAuth2ClientAuthenticationToken(
            Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
    
    private SessionInformation getSessionInformation(Authentication principal) {
        SessionInformation sessionInformation = null;
        if (this.sessionRegistry != null) {
            List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal.getPrincipal(), false);
            if (!CollectionUtils.isEmpty(sessions)) {
                sessionInformation = sessions.getFirst();
                if (sessions.size() > 1) {
                    sessions = new ArrayList<>(sessions);
                    sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
                    sessionInformation = sessions.getLast();
                }
            }
        }
        return sessionInformation;
    }
    
    /**
     * 将给定的字符串值转换为SHA-256哈希值，并以Base64编码的形式返回 此方法用于生成给定文本的唯一标识符，常用于数据校验和加密场景
     *
     * @param value 需要转换为哈希值的原始字符串
     * @return 返回经过SHA-256哈希处理并使用Base64编码的字符串
     * @throws NoSuchAlgorithmException 如果Java安全API不支持SHA-256算法，则抛出此异常
     */
    private static String createHash(String value) throws NoSuchAlgorithmException {
        // 获取SHA-256算法的消息摘要实例
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // 使用ASCII字符集将输入字符串转换为字节数组，然后计算哈希值
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        // 使用Base64对哈希值进行编码，选择URL安全的编码方式并去除填充字符
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
