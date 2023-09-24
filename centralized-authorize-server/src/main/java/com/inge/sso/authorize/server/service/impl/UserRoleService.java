package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.UserRoleEntity;
import com.inge.sso.authorize.server.mapper.UserRoleMapper;
import com.inge.sso.authorize.server.service.IUserRoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
@RequiredArgsConstructor
public class UserRoleService extends ServiceImpl<UserRoleMapper, UserRoleEntity> implements IUserRoleService {
}
