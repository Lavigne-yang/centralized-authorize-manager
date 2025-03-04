package com.archie.sso.authorize.server.authorization.pwd.converter;

import com.archie.sso.authorize.server.authorization.pwd.token.PasswordGrantAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Slf4j
public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {
    
    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://bing.com";
    
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            log.debug("not supported grant type: password");
            return null;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        MultiValueMap<String, String> parameters = getParameters(request);
        
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            throw new RuntimeException(
                    OAuth2ErrorCodes.INVALID_REQUEST + ": " + OAuth2ParameterNames.SCOPE + ": " + scope);
        }
        Set<String> requestScopes = null;
        if (StringUtils.hasText(scope)) {
            requestScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, values) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.SCOPE) && !key.equals(
                    OAuth2ParameterNames.CLIENT_ID)) {
                additionalParameters.put(key, values.get(0));
            }
        });
        return new PasswordGrantAuthenticationToken(AuthorizationGrantType.PASSWORD, authentication, requestScopes,
                additionalParameters);
    }
    
    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
