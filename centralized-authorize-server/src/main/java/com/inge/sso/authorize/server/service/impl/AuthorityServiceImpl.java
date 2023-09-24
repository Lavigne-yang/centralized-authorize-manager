package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.inge.sso.authorize.server.entity.AuthorityEntity;
import com.inge.sso.authorize.server.mapper.AuthorityMapper;
import com.inge.sso.authorize.server.service.IAuthorityService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
@RequiredArgsConstructor
public class AuthorityServiceImpl extends ServiceImpl<AuthorityMapper, AuthorityEntity> implements IAuthorityService {
}
