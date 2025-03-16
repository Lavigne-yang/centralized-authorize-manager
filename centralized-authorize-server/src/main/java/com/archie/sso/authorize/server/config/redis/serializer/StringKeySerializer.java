package com.archie.sso.authorize.server.config.redis.serializer;

import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

/**
 * @author lavyoung1325 <2034549297@qq.com>
 * Created on 2025-03-16
 */
public class StringKeySerializer implements RedisSerializer<String> {

    private final String keyPrefix;

    public StringKeySerializer(String keyPrefix) {
        this.keyPrefix = keyPrefix;
    }


    @Override
    public byte[] serialize(String value) throws SerializationException {
        if (value == null) {
            return null;
        }
        return (keyPrefix + ":" + value).getBytes();
    }

    @Override
    public String deserialize(byte[] bytes) throws SerializationException {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        String key = new String(bytes);
        if (key.startsWith(keyPrefix + ":")) {
            return key.substring(keyPrefix.length() + 1);
        }
        throw new SerializationException("Deserialized key does not start with the expected prefix: " + keyPrefix);
    }
}
