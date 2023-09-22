package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.io.Serializable;
import java.util.Objects;

/**
 * @author lavyoung
 */
@Data
@TableName("cam_role")
public class RoleEntity implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String roleName;
    private Integer deleted;
    private Integer sort;
    private Long createTime;
    private Long updateTime;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        RoleEntity that = (RoleEntity) o;
        return Objects.equals(id, that.id) && Objects.equals(roleName, that.roleName) && Objects.equals(deleted, that.deleted) && Objects.equals(sort, that.sort) && Objects.equals(createTime, that.createTime) && Objects.equals(updateTime, that.updateTime);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, roleName, deleted, sort, createTime, updateTime);
    }
}
