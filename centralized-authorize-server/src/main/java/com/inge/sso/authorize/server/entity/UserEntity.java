package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.FieldFill;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.inge.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Objects;

/**
 * 实现自定义的User对象
 *
 * @author lavyoung1325
 */
@Data
@TableName("cam_user")
@JsonSerialize
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserEntity implements Serializable, UserDetails {

    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

    @TableId("user_id")
    private String userId;
    private String account;
    /**
     * 此为用户自定义、用户名可重复，不能用于登陆
     */
    private String nickName;
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
     * @return
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
        return Objects.equals(userId, that.userId) && Objects.equals(account, that.account) && Objects.equals(nickName, that.nickName) && Objects.equals(password, that.password) && Objects.equals(mobile, that.mobile) && Objects.equals(email, that.email) && Objects.equals(avatarUrl, that.avatarUrl) && Objects.equals(sourceFrom, that.sourceFrom) && Objects.equals(enable, that.enable) && Objects.equals(createTime, that.createTime) && Objects.equals(updateTime, that.updateTime) && Objects.equals(authorities, that.authorities);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, account, nickName, password, mobile, email, avatarUrl, sourceFrom, enable, createTime, updateTime, authorities);
    }
}
