package com.archie.sso.authorize.entity.role;

import com.archie.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;

/**
 * @author lavyoung
 */
@Data
public class RoleEntity implements Serializable {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    
    private String id;
    
    private String roleName;
    
    private Integer deleted;
    
    private Integer sort;
    
    private Long createTime;
    
    private Long updateTime;
}
