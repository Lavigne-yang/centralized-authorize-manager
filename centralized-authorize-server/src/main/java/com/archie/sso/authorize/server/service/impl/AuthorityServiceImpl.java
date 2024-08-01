package com.archie.sso.authorize.server.service.impl;

import com.archie.sso.authorize.server.entity.AuthorityEntity;
import com.archie.sso.authorize.server.mapper.AuthorityMapper;
import com.archie.sso.authorize.server.service.AuthorityService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author lavyoung1325
 */
@Service
@RequiredArgsConstructor
public class AuthorityServiceImpl extends ServiceImpl<AuthorityMapper, AuthorityEntity> implements AuthorityService {
}
