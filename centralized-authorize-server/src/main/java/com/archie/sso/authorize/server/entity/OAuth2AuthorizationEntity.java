package com.archie.sso.authorize.server.entity;

import com.archie.sso.authorize.common.utils.CamAuthorizationServerVersion;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * CREATE TABLE cam_oauth2_authorization
 * (
 *     id                            varchar(100) NOT NULL,
 *     registered_client_id          varchar(100) NOT NULL,
 *     principal_name                varchar(200) NOT NULL,
 *     authorization_grant_type      varchar(100) NOT NULL,
 *     authorized_scopes             varchar(1000) DEFAULT NULL,
 *     attributes                    blob          DEFAULT NULL,
 *     state                         varchar(500)  DEFAULT NULL,
 *     authorization_code_value      blob          DEFAULT NULL,
 *     authorization_code_issued_at  timestamp     DEFAULT NULL,
 *     authorization_code_expires_at timestamp     DEFAULT NULL,
 *     authorization_code_metadata   blob          DEFAULT NULL,
 *     access_token_value            blob          DEFAULT NULL,
 *     access_token_issued_at        timestamp     DEFAULT NULL,
 *     access_token_expires_at       timestamp     DEFAULT NULL,
 *     access_token_metadata         blob          DEFAULT NULL,
 *     access_token_type             varchar(100)  DEFAULT NULL,
 *     access_token_scopes           varchar(1000) DEFAULT NULL,
 *     oidc_id_token_value           blob          DEFAULT NULL,
 *     oidc_id_token_issued_at       timestamp     DEFAULT NULL,
 *     oidc_id_token_expires_at      timestamp     DEFAULT NULL,
 *     oidc_id_token_metadata        blob          DEFAULT NULL,
 *     refresh_token_value           blob          DEFAULT NULL,
 *     refresh_token_issued_at       timestamp     DEFAULT NULL,
 *     refresh_token_expires_at      timestamp     DEFAULT NULL,
 *     refresh_token_metadata        blob          DEFAULT NULL,
 *     user_code_value               blob          DEFAULT NULL,
 *     user_code_issued_at           timestamp     DEFAULT NULL,
 *     user_code_expires_at          timestamp     DEFAULT NULL,
 *     user_code_metadata            blob          DEFAULT NULL,
 *     device_code_value             blob          DEFAULT NULL,
 *     device_code_issued_at         timestamp     DEFAULT NULL,
 *     device_code_expires_at        timestamp     DEFAULT NULL,
 *     device_code_metadata          blob          DEFAULT NULL,
 *     PRIMARY KEY (id)
 * );
 * @author lavyoung1325
 * @since 1.0.0
 */
@Data
@TableName("cam_oauth2_authorization")
public class OAuth2AuthorizationEntity implements Serializable {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

    @TableId("id")
    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private String authorizedScopes;
    private String attributes;
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
    private String userCodeValue;
    private Instant userCodeIssuedAt;
    private Instant userCodeExpiresAt;
    private String userCodeMetadata;
    private String deviceCodeValue;
    private Instant deviceCodeIssuedAt;
    private Instant deviceCodeExpiresAt;
    private String deviceCodeMetadata;
}
