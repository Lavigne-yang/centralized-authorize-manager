package com.archie.sso.authorize.server.service.impl;

import com.archie.sso.authorize.server.entity.UserRoleEntity;
import com.archie.sso.authorize.server.mapper.UserRoleMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
public class UserRoleService extends ServiceImpl<UserRoleMapper, UserRoleEntity>
        implements com.archie.sso.authorize.server.service.UserRoleService {
}
