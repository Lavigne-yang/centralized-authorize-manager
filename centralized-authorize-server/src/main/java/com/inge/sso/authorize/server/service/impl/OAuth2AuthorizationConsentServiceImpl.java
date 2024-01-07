package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.OAuth2AuthorizationConsentEntity;
import com.inge.sso.authorize.server.mapper.OAuth2AuthorizationConsentMapper;
import com.inge.sso.authorize.server.service.AuthorizationConsentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author lavyoung1325
 */
@Service
public class OAuth2AuthorizationConsentServiceImpl extends ServiceImpl<OAuth2AuthorizationConsentMapper, OAuth2AuthorizationConsentEntity> implements OAuth2AuthorizationConsentService, AuthorizationConsentService {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        OAuth2AuthorizationConsent existingAuthorizationConsent = findById(authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
        if (existingAuthorizationConsent == null) {
            this.baseMapper.insert(dataToRow(authorizationConsent));
        } else {
            this.baseMapper.updateByClientIdAndPrincipalName(dataToRow(authorizationConsent));
        }
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.baseMapper.deleteByClientIdAndPrincipalName(dataToRow(authorizationConsent));
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        List<OAuth2AuthorizationConsentEntity> consentEntities = this.baseMapper.selectList(Wrappers.lambdaQuery(OAuth2AuthorizationConsentEntity.class).eq(OAuth2AuthorizationConsentEntity::getRegisteredClientId, registeredClientId).eq(OAuth2AuthorizationConsentEntity::getPrincipalName, principalName));
        return CollectionUtils.isEmpty(consentEntities) ? null : rowToData(consentEntities.get(0));
    }

    private OAuth2AuthorizationConsent rowToData(OAuth2AuthorizationConsentEntity authorizationConsent) {
        String registeredClientId = authorizationConsent.getRegisteredClientId();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(registeredClientId);
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
        }
        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(registeredClientId, authorizationConsent.getPrincipalName());
        if (authorizationConsent.getAuthorities() != null) {
            for (String authority : StringUtils.commaDelimitedListToSet(authorizationConsent.getAuthorities())) {
                builder.authority(new SimpleGrantedAuthority(authority));
            }
        }
        return builder.build();
    }


    private OAuth2AuthorizationConsentEntity dataToRow(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity entity = new OAuth2AuthorizationConsentEntity();
        entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        entity.setPrincipalName(authorizationConsent.getPrincipalName());
        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : authorizationConsent.getAuthorities()) {
            authorities.add(authority.getAuthority());
        }
        entity.setAuthorities(StringUtils.collectionToDelimitedString(authorities, ","));
        return entity;
    }

}
