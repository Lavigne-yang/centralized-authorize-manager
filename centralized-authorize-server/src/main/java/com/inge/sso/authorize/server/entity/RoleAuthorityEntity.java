package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import com.inge.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;

import java.io.Serializable;
import java.util.Objects;

/**
 * @author lavyoung1325
 */
@Data
@TableName("cam_role_authority")
public class RoleAuthorityEntity implements Serializable {

    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

    private String id;
    private String roleId;
    private String authorityId;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        RoleAuthorityEntity that = (RoleAuthorityEntity) o;
        return Objects.equals(id, that.id) && Objects.equals(roleId, that.roleId) && Objects.equals(authorityId, that.authorityId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, roleId, authorityId);
    }
}
