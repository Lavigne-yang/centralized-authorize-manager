package com.inge.sso.authorize.server.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.inge.sso.authorize.server.entity.OAuth2AuthorizationConsentEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface OAuth2AuthorizationConsentMapper extends BaseMapper<OAuth2AuthorizationConsentEntity> {
}
