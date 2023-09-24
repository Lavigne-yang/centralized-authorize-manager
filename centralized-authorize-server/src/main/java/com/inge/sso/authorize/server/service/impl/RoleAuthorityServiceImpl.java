package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.RoleAuthorityEntity;
import com.inge.sso.authorize.server.mapper.RoleAuthorityMapper;
import com.inge.sso.authorize.server.service.IRoleAuthorityService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
@RequiredArgsConstructor
public class RoleAuthorityServiceImpl extends ServiceImpl<RoleAuthorityMapper, RoleAuthorityEntity> implements IRoleAuthorityService {
}
