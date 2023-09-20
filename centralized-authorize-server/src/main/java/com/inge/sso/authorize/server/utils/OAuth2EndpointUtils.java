package com.inge.sso.authorize.server.utils;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * @author lavyoung1325
 */
public class OAuth2EndpointUtils {

    public static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private OAuth2EndpointUtils() {

    }

    /**
     * 获取请求头的参数集合
     *
     * @param request
     * @return
     */
    public static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, value) -> {
            if (value.length > 0) {
                for (String v : value) {
                    parameters.add(key, v);
                }
            }
        });
        return parameters;
    }

    private static boolean matchesPkceTokenRequest(HttpServletRequest request) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
                request.getParameter(OAuth2ParameterNames.GRANT_TYPE)) &&
                request.getParameter(OAuth2ParameterNames.CODE) != null &&
                request.getParameter(PkceParameterNames.CODE_VERIFIER) != null;
    }

    public static void throwError(String errorCode, String parameterName, String errorUrl) {
        OAuth2Error auth2Error = new OAuth2Error(errorCode, "OAuth 2,0 paramter: " + parameterName, errorUrl);
        throw new OAuth2AuthenticationException(auth2Error);
    }

}
