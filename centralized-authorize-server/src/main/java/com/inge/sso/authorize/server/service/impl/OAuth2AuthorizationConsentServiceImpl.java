package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.OAuth2AuthorizationConsentEntity;
import com.inge.sso.authorize.server.mapper.OAuth2AuthorizationConsentMapper;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;

@Service
public class OAuth2AuthorizationConsentServiceImpl extends ServiceImpl<OAuth2AuthorizationConsentMapper, OAuth2AuthorizationConsentEntity> implements OAuth2AuthorizationConsentService {
    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {

    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {

    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        return null;
    }
}
