package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.RoleEntity;
import com.inge.sso.authorize.server.mapper.RoleMapper;
import com.inge.sso.authorize.server.service.IRoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
@RequiredArgsConstructor
public class RoleServiceImpl extends ServiceImpl<RoleMapper, RoleEntity> implements IRoleService {
}
