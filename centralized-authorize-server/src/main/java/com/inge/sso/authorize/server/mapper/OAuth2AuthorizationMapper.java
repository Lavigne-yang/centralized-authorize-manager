package com.inge.sso.authorize.server.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.inge.sso.authorize.server.entity.OAuth2AuthorizationEntity;
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
