package com.archie.sso.authorize.server.entity;

import com.archie.sso.authorize.common.utils.CamAuthorizationServerVersion;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * 用户角色
 * @author lavyoung1325
 */
@Data
@TableName("cam_user_role")
public class UserRoleEntity implements Serializable {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    @TableId("id")
    private String id;
    private String userId;
    private String roleId;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UserRoleEntity that = (UserRoleEntity) o;
        return Objects.equals(id, that.id) && Objects.equals(userId, that.userId) && Objects.equals(roleId, that.roleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, userId, roleId);
    }
}
