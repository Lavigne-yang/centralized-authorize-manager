package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.inge.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * @author lavyoung1325
 * @since 1.0.0
 */
@Data
@TableName("cam_oauth2_authorization")
public class OAuth2AuthorizationEntity implements Serializable {

    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

    @TableId("id")
    private String id;
    private String registeredClientId;
    private String principalName;
    private AuthorizationGrantType authorizationGrantType;
    private Set<String> authorizedScopes;
    private Map<String, Object> attributes;
    private String state;
    private String authorizationCodeValue;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    private String authorizationCodeMetadata;
    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    private String accessTokenMetadata;
    private String accessTokenType;
    private String accessTokenScopes;
    private String oidcIdTokenValue;
    private Instant oidcIdTokenIssuedAt;
    private Instant oidcIdTokenExpiresAt;
    private String oidcIdTokenMetadata;
    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;
    private String refreshTokenMetadata;
}
