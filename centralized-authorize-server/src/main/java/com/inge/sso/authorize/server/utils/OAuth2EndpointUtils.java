package com.inge.sso.authorize.server.utils;

import com.inge.sso.authorize.common.constants.CamOauthConstants;
import com.inge.sso.authorize.common.constants.ExceptionConstants;
import com.inge.sso.authorize.common.utils.JsonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author lavyoung1325
 */
public final class OAuth2EndpointUtils {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2EndpointUtils.class);

    public static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private OAuth2EndpointUtils() {
        // 禁止实例化工具类
        throw new UnsupportedOperationException("Utility classes cannot be instantiated.");
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

    /**
     * 鉴权失败返回处理
     *
     * @param request  请求
     * @param response 响应
     * @param thr      异常
     */
    public static void exceptionHandler(HttpServletRequest request, HttpServletResponse response, Throwable thr) {
        Map<String, String> parameters = getErrorParameters(request, response, thr);
        String wwwAuthenticateHeaderValue = computeWwwAuthenticateHeaderValue(parameters);
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeaderValue);

        try {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(JsonUtil.objectCovertToJson(parameters));
            response.getWriter().close();
        } catch (IOException e) {
            logger.error("失败返回错误：", e);
        }
    }

    /**
     * 获取异常信息map
     *
     * @param request
     * @param response
     * @param thr      本次异常具体的异常实例
     * @return
     */
    private static Map<String, String> getErrorParameters(HttpServletRequest request, HttpServletResponse response, Throwable thr) {
        Map<String, String> parameters = new LinkedHashMap<>();
        if (request.getUserPrincipal() instanceof AbstractAuthenticationToken) {
            // 权限不足
            parameters.put(ExceptionConstants.ERROR, BearerTokenErrorCodes.INSUFFICIENT_SCOPE);
            parameters.put(ExceptionConstants.ERROR_DESCRIPTION, "The request requires higher privileges than provided by the access token.");
            parameters.put(ExceptionConstants.ERROR_URI, ExceptionConstants.ERROR_URL);
            response.setStatus(HttpStatus.FORBIDDEN.value());
        }
        if (thr instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) thr).getError();
            parameters.put(ExceptionConstants.ERROR, error.getErrorCode());
            if (StringUtils.hasText(error.getUri())) {
                parameters.put(ExceptionConstants.ERROR_URI, error.getUri());
            }
            if (StringUtils.hasText(error.getDescription())) {
                parameters.put(ExceptionConstants.ERROR_DESCRIPTION, error.getDescription());
            }
            if (error instanceof BearerTokenError) {
                BearerTokenError bearerTokenError = (BearerTokenError) error;
                if (StringUtils.hasText(bearerTokenError.getScope())) {
                    parameters.put(ExceptionConstants.SCOPE, bearerTokenError.getScope());
                }
                response.setStatus(bearerTokenError.getHttpStatus().value());
            }
        }
        if (thr instanceof InsufficientAuthenticationException) {
            // 没有携带jwt访问接口，没有客户端认证信息
            parameters.put(ExceptionConstants.ERROR, BearerTokenErrorCodes.INVALID_TOKEN);
            parameters.put(ExceptionConstants.ERROR_DESCRIPTION, "Not authorized.");
            parameters.put(ExceptionConstants.ERROR_URI, ExceptionConstants.ERROR_URL);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }
        parameters.put(ExceptionConstants.ERROR_MESSAGE, thr.getMessage());
        return parameters;
    }

    /**
     * 生成放入请求头的错误信息
     *
     * @param parameters 参数
     * @return 字符串
     */
    private static String computeWwwAuthenticateHeaderValue(Map<String, String> parameters) {
        StringBuilder wwwAuthorize = new StringBuilder();
        wwwAuthorize.append(CamOauthConstants.TOKEN_PREFIX);
        if (!parameters.isEmpty()) {
            wwwAuthorize.append(" ");
            int i = 0;
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                wwwAuthorize.append(entry.getKey()).append("=\"")
                        .append(entry.getValue()).append("\"");
                if (i != parameters.size() - 1) {
                    wwwAuthorize.append(", ");
                }
                i++;
            }
        }
        return wwwAuthorize.toString();
    }
}
