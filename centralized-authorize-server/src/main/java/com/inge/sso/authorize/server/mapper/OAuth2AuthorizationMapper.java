package com.inge.sso.authorize.server.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.inge.sso.authorize.server.entity.OAuth2AuthorizationEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface OAuth2AuthorizationMapper extends BaseMapper<OAuth2AuthorizationEntity> {
}
