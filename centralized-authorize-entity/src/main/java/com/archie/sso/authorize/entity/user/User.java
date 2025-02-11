package com.archie.sso.authorize.entity.user;

import com.archie.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

/**
 * @author lavyoung1325
 */
@Data
public class User implements Serializable {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    
    private String userId;
    
    private String account;
    
    private String username;
    
    private String password;
    
    private String mobile;
    
    private String email;
    
    private String avatarUrl;
    
    private String sourceFrom;
    
    private Boolean enable;
    
    private Long createTime;
    
    private Long updateTime;
    
    private List<String> authorities;
    
}
