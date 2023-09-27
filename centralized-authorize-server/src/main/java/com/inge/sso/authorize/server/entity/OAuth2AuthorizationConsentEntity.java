package com.inge.sso.authorize.server.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.util.SpringAuthorizationServerVersion;

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

    private static final long serialVersionUID = SpringAuthorizationServerVersion.SERIAL_VERSION_UID;
    private static final String AUTHORITIES_SCOPE_PREFIX = "SCOPE_";

    private String registeredClientId;
    private String principalName;
    private Set<GrantedAuthority> authorities;

    public Set<String> getScopes() {
        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : getAuthorities()) {
            if (authority.getAuthority().startsWith(AUTHORITIES_SCOPE_PREFIX)) {
                authorities.add(authority.getAuthority().replaceFirst(AUTHORITIES_SCOPE_PREFIX, ""));
            }
        }
        return authorities;
    }
}
