package com.archie.sso.authorize.server.generator.token;

import java.util.UUID;

import org.springframework.security.crypto.keygen.StringKeyGenerator;

/**
 * uuid
 *
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-15
 */
public class UUIDKeyGenerator implements StringKeyGenerator {
    @Override
    public String generateKey() {
        return UUID.randomUUID().toString().toLowerCase();
    }
}
