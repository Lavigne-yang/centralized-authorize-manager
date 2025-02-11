package com.archie.sso.authorize.entity.role;

import com.archie.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;

/**
 * 用户角色
 *
 * @author lavyoung1325
 */
@Data
public class UserRole implements Serializable {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    
    private String id;
    
    private String userId;
    
    private String roleId;
    
}
