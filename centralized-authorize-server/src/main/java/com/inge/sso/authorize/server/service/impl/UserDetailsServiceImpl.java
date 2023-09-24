package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.AuthorityEntity;
import com.inge.sso.authorize.server.entity.RoleAuthorityEntity;
import com.inge.sso.authorize.server.entity.UserEntity;
import com.inge.sso.authorize.server.entity.UserRoleEntity;
import com.inge.sso.authorize.server.mapper.UserMapper;
import com.inge.sso.authorize.server.service.IAuthorityService;
import com.inge.sso.authorize.server.service.IRoleAuthorityService;
import com.inge.sso.authorize.server.service.IUserRoleService;
import com.inge.sso.authorize.server.service.IUserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


/**
 * Created by IntelliJ IDEA.
 * @Author : lavyoung1325
 * @create 2023/9/24
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl extends ServiceImpl<UserMapper, UserEntity> implements UserDetailsService, IUserService {

    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    private final IUserRoleService userRoleService;

    private final IAuthorityService authorityService;

    private final IRoleAuthorityService roleAuthorityService;

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserEntity user = null;
        try {
            // username字段在用户登录时一般可能是用户账号、手机号、邮箱
            // 因此数据库中存储的username字段可能是手机号、邮箱、也能都是，需要根据输入内容进行登录校验
            user = baseMapper.selectOne(Wrappers.lambdaQuery(UserEntity.class)
                    .or(o -> o.eq(UserEntity::getEmail, username))
                    .or(o -> o.eq(UserEntity::getMobile, username))
                    .or(o -> o.eq(UserEntity::getAccount, username)));
            if (user == null) {
                throw new UsernameNotFoundException("账号不存在");
            }
            // 查询用户关联的角色信息
            List<UserRoleEntity> userRoleList = userRoleService.list(Wrappers.lambdaQuery(UserRoleEntity.class).eq(UserRoleEntity::getUserId, user.getUserId()));
            List<String> roleIds = Optional.ofNullable(userRoleList).orElse(Collections.emptyList()).stream().map(UserRoleEntity::getRoleId).collect(Collectors.toList());
            if (roleIds.isEmpty()) {
                return user;
            }
            // 角色不为空需要返回用户的权限
            List<RoleAuthorityEntity> roleAuthorityList = roleAuthorityService.list(Wrappers.lambdaQuery(RoleAuthorityEntity.class).in(RoleAuthorityEntity::getRoleId, roleIds));
            List<String> authorityIds = Optional.ofNullable(roleAuthorityList).orElse(Collections.emptyList()).stream().map(RoleAuthorityEntity::getAuthorityId).collect(Collectors.toList());
            if (authorityIds.isEmpty()) {
                return user;
            }
            // 查询权限
            List<AuthorityEntity> authorityList = authorityService.list(Wrappers.lambdaQuery(AuthorityEntity.class).in(AuthorityEntity::getId, authorityIds));
            user.setAuthorities(authorityList);
        } catch (Exception e) {
            logger.error("error:", e);
        }
        return user;
    }
}
