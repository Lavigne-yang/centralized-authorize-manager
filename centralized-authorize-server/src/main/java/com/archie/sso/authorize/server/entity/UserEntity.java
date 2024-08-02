package com.archie.sso.authorize.server.entity;

import com.archie.sso.authorize.common.utils.CamAuthorizationServerVersion;
import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Objects;

/**
 * create table cam_user
 * (
 *     user_id     varchar(100)         not null comment '用户id' primary key,
 *     account     varchar(150)         not null comment '账户',
 *     username    varchar(150)         not null comment '用户名',
 *     password    varchar(200)         not null comment '密码',
 *     mobile      varchar(30)          null comment '手机号',
 *     email       varchar(200)         not null comment '邮箱',
 *     avatar_url  varchar(500)         null comment '头像地址',
 *     source_from tinyint    default 1 not null comment '用户来源',
 *     enable      tinyint(1) default 1 not null comment '是否启用',
 *     create_time bigint               not null comment '创建时间',
 *     update_time bigint               not null comment '更新时间'
 * ) comment '用户数据';
 * 实现自定义的User对象
 *
 * @author lavyoung1325
 */
@Data
@TableName("cam_user")
@JsonSerialize
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserEntity implements Serializable, UserDetails {
    
    @Serial
    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

    @TableId("user_id")
    private String userId;
    private String account;
    /**
     * 此为用户自定义、用户名可重复，不能用于登陆
     */
    private String username;
    private String password;
    private String mobile;
    private String email;
    private String avatarUrl;
    private String sourceFrom;
    private Boolean enable;
    @TableField(fill = FieldFill.INSERT)
    private Long createTime;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Long updateTime;

    /**
     * 权限
     */
    @TableField(exist = false)
    private Collection<? extends GrantedAuthority> authorities;

    /**
     * 用户权限
     *
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.account;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.enable;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.enable;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.enable;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserEntity that = (UserEntity) o;
        return Objects.equals(userId, that.userId) && Objects.equals(account, that.account) && Objects.equals(username,
                that.username) && Objects.equals(password, that.password) && Objects.equals(mobile, that.mobile)
                && Objects.equals(email, that.email) && Objects.equals(avatarUrl, that.avatarUrl) && Objects.equals(
                sourceFrom, that.sourceFrom) && Objects.equals(enable, that.enable) && Objects.equals(createTime,
                that.createTime) && Objects.equals(updateTime, that.updateTime) && Objects.equals(authorities,
                that.authorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, account, username, password, mobile, email, avatarUrl, sourceFrom, enable,
                createTime, updateTime, authorities);
    }
}
