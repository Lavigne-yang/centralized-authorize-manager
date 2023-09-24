package com.inge.sso.authorize.common.dto;

import lombok.Data;

import java.util.Collection;
import java.util.Objects;

/**
 * Created by IntelliJ IDEA.
 * @Author : lavyoung1325
 * @create 2023/9/24
 */
@Data
public class User {

    private String userId;
    private String account;
    private String nickName;
    private String password;
    private String mobile;
    private String email;
    private String avatarUrl;
    private String sourceFrom;
    private Boolean enable;
    private Long createTime;
    private Long updateTime;
    private Collection<Objects> authorities;
}
