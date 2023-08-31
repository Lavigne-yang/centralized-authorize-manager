package com.inge.sso.authorize.common.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * @author lavyoung1325
 */
@Data
@TableName("oauth2_authorization")
public class AuthorizationEntity {

    @TableId
    private String id;

    private String registeredClientId;

    private String principalName;

    private String authorizationGrantType;

    private String authorizedScopes;

    private String attributes;

    private String state;

    private String authorizationCodeValue;

    private Long authorizationCodeIssuedAt;

    private Long authorizationCodeExpiresAt;

    private String authorizationCodeMetadata;

    private String accessTokenValue;

    private Long accessTokenIssuedAt;

    private Long accessTokenExpiresAt;

    private String accessTokenMetadata;

    private String accessTokenType;

    private String accessTokenScopes;

    private String oidcIdTokenValue;

    private Long oidcIdTokenIssuedAt;

    private Long oidcIdTokenExpiresAt;

    private String oidcIdTokenMetadata;

    private String refreshTokenValue;

    private Long refreshTokenIssuedAt;

    private Long refreshTokenExpiresAt;

    private String refreshTokenMetadata;
}
