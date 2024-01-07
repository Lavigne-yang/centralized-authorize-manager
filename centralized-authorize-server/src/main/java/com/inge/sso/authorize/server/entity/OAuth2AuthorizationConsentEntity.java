package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import com.inge.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;

import java.io.Serializable;

/**
 * @author lavyoung1325
 * @since 1.0.0
 */
@Data
@TableName("cam_oauth2_authorization_consent")
public class OAuth2AuthorizationConsentEntity implements Serializable {

    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    private String registeredClientId;
    private String principalName;
    private String authorities;
}
