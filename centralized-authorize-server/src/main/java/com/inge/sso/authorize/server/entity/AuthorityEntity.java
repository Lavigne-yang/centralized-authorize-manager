package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.inge.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Objects;

/**
 * 系统菜单权限
 *
 * @author lavyoung1325
 */
@Data
@TableName("cam_system_authority")
public class AuthorityEntity implements Serializable, GrantedAuthority {

    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;;

    private String id;
    private String menuName;
    private String menuParentId;
    private String path;
    private String authority;
    private Integer sort;
    private Integer type;
    private Integer deleted;
    @TableField(fill = FieldFill.INSERT)
    private Long createTime;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Long updateTime;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthorityEntity that = (AuthorityEntity) o;
        return Objects.equals(id, that.id) && Objects.equals(menuName, that.menuName) && Objects.equals(menuParentId, that.menuParentId) && Objects.equals(path, that.path) && Objects.equals(authority, that.authority) && Objects.equals(sort, that.sort) && Objects.equals(type, that.type) && Objects.equals(deleted, that.deleted) && Objects.equals(createTime, that.createTime) && Objects.equals(updateTime, that.updateTime);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, menuName, menuParentId, path, authority, sort, type, deleted, createTime, updateTime);
    }
}
