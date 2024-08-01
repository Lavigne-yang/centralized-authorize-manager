package com.archie.sso.authorize.server.mapper;

import com.archie.sso.authorize.server.entity.OAuth2AuthorizationEntity;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * Created by IntelliJ IDEA
 *
 * @author : lavyoung1325
 * @create 2023/9/28
 */
@Mapper
public interface OAuth2AuthorizationMapper extends BaseMapper<OAuth2AuthorizationEntity> {
}
