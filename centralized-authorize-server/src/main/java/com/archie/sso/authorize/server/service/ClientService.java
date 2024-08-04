package com.archie.sso.authorize.server.service;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import com.archie.sso.authorize.server.entity.ClientEntity;
import com.baomidou.mybatisplus.extension.service.IService;

/**
 * @author lavyoung
 */
public interface ClientService extends IService<ClientEntity>, RegisteredClientRepository {
}
