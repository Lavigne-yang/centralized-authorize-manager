package com.archie.sso.authorize.server.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.archie.sso.authorize.server.entity.UserEntity;
import com.baomidou.mybatisplus.extension.service.IService;

/**
 * @author lavyoung1325
 */
public interface UserService extends IService<UserEntity>, UserDetailsService {
}
