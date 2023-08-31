package com.inge.sso.authorize.server.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * @author lavyoung1325
 */
public class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private static final Logger logger = LoggerFactory.getLogger(UserRepositoryOAuth2UserHandler.class);

    private final UserRepository userRepository = new UserRepository();

    @Override
    public void accept(OAuth2User user) {
        if (this.userRepository.findByName(user.getName()) == null) {
            logger.info("save user: user name={}, claims={}, authorities=={}", user.getName(), user.getAttributes(), user.getAuthorities());
            this.userRepository.save(user);
        }
    }


    static class UserRepository {

        private final Map<String, OAuth2User> userCache = new ConcurrentHashMap<>();

        public OAuth2User findByName(String name) {
            return this.userCache.get(name);
        }

        public void save(OAuth2User oAuth2User) {
            this.userCache.put(oAuth2User.getName(), oAuth2User);
        }

    }
}
