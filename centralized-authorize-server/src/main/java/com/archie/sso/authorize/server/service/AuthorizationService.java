package com.archie.sso.authorize.server.service;

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

import com.archie.sso.authorize.server.entity.OAuth2AuthorizationEntity;
import com.baomidou.mybatisplus.extension.service.IService;

/**
 * 授权管理
 *
 * @author lavyoung1325
 */
public interface AuthorizationService extends IService<OAuth2AuthorizationEntity>, OAuth2AuthorizationService {

}
