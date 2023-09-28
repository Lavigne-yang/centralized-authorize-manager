package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import com.inge.sso.authorize.common.utils.CamAuthorizationServerVersion;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * @author lavyoung1325
 * @since 1.0.0
 */
@Data
@TableName("cam_oauth2_authorization_consent")
public class OAuth2AuthorizationConsentEntity implements Serializable {

    private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;
    private static final String AUTHORITIES_SCOPE_PREFIX = "SCOPE_";

    private String registeredClientId;
    private String principalName;
    private Set<GrantedAuthority> authorities;

    public OAuth2AuthorizationConsentEntity(String registeredClientId, String principalName, Set<GrantedAuthority> authorities) {
        this.registeredClientId = registeredClientId;
        this.principalName = principalName;
        this.authorities = authorities;
    }

    public Set<String> getScopes() {
        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : getAuthorities()) {
            if (authority.getAuthority().startsWith(AUTHORITIES_SCOPE_PREFIX)) {
                authorities.add(authority.getAuthority().replaceFirst(AUTHORITIES_SCOPE_PREFIX, ""));
            }
        }
        return authorities;
    }

    public static Builder from(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        return new Builder(authorizationConsent);
    }


    @Data
    public static class Builder implements Serializable {
        private static final long serialVersionUID = CamAuthorizationServerVersion.SERIAL_VERSION_UID;

        private String registeredClientId;
        private String principalName;
        private Set<GrantedAuthority> authorities = new HashSet<>();

        protected Builder() {

        }

        protected Builder(OAuth2AuthorizationConsent authorizationConsent) {
            this.registeredClientId = authorizationConsent.getRegisteredClientId();
            this.principalName = authorizationConsent.getPrincipalName();
            if (!CollectionUtils.isEmpty(authorizationConsent.getAuthorities())) {
                this.authorities.addAll(authorizationConsent.getAuthorities());
            }
        }

        public OAuth2AuthorizationConsentEntity builder() {
            Assert.hasText(registeredClientId, "registeredClientId cannot be null");
            Assert.hasText(principalName, "principalName cannot be null");
            Assert.notEmpty(this.authorities, "authorities cannot be empty");
            return new OAuth2AuthorizationConsentEntity(registeredClientId, principalName, authorities);
        }

    }
}
