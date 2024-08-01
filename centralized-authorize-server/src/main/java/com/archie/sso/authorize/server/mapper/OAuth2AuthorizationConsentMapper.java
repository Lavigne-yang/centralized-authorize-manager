package com.archie.sso.authorize.server.mapper;

import com.archie.sso.authorize.server.entity.OAuth2AuthorizationConsentEntity;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * Created by IntelliJ IDEA.
 *
 * @author : lavyoung1325
 * @create 2023/9/28
 */
@Mapper
public interface OAuth2AuthorizationConsentMapper extends BaseMapper<OAuth2AuthorizationConsentEntity> {

    /**
     * 删除
     *
     * @param consentEntity
     */
    void deleteByClientIdAndPrincipalName(OAuth2AuthorizationConsentEntity consentEntity);


    /**
     * 更新
     *
     * @param oAuth2AuthorizationConsentEntity
     */
    void updateByClientIdAndPrincipalName(OAuth2AuthorizationConsentEntity oAuth2AuthorizationConsentEntity);
}
