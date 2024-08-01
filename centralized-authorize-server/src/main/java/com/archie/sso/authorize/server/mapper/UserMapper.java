package com.archie.sso.authorize.server.mapper;

import com.archie.sso.authorize.server.entity.UserEntity;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * @author lavyoung1325
 */
@Mapper
public interface UserMapper extends BaseMapper<UserEntity> {
}
