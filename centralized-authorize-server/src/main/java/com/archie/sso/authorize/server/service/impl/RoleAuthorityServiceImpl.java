package com.archie.sso.authorize.server.service.impl;

import com.archie.sso.authorize.server.entity.RoleAuthorityEntity;
import com.archie.sso.authorize.server.mapper.RoleAuthorityMapper;
import com.archie.sso.authorize.server.service.RoleAuthorityService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
@RequiredArgsConstructor
public class RoleAuthorityServiceImpl extends ServiceImpl<RoleAuthorityMapper, RoleAuthorityEntity> implements RoleAuthorityService {

}
