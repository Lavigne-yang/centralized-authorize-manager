package com.inge.sso.authorize.server.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.inge.sso.authorize.server.entity.UserEntity;
import org.apache.ibatis.annotations.Mapper;

/**
 * @author lavyoung1325
 */
@Mapper
public interface UserMapper extends BaseMapper<UserEntity> {
}
