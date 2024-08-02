package com.archie.sso.authorize.server.service.impl;

import com.archie.sso.authorize.server.entity.RoleEntity;
import com.archie.sso.authorize.server.mapper.RoleMapper;
import com.archie.sso.authorize.server.service.RoleService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
public class RoleServiceImpl extends ServiceImpl<RoleMapper, RoleEntity> implements RoleService {
}
