package com.inge.sso.authorize.server.authorization.pwd;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.*;

/**
 * 自定义Oauth2 密码模式认证Token
 *
 * @author lavyoung1325
 */
public class OAuth2ResourceOwnerPasswordAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -6067207202119450764L;

    private final AuthorizationGrantType authorizationGrantType;
    private final Authentication clientPrincipal;
    private final Set<String> scopes;
    private final Map<String, Object> additionalParameters;

    /**
     * Creates a token with the supplied array of authorities.
     * <p>
     * super            the collection of <tt>GrantedAuthority</tt>s for the principal
     * represented by this authentication object.
     *
     * @param authorizationGrantType
     * @param clientPrincipal
     * @param scopes
     * @param additionalParameters
     */
    public OAuth2ResourceOwnerPasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType, Authentication clientPrincipal, Set<String> scopes, Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.authorizationGrantType = authorizationGrantType;
        this.clientPrincipal = clientPrincipal;
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
        this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
    }

    /**
     * Returns the authorization grant type.
     *
     * @return
     */
    public AuthorizationGrantType getAuthorizationGrantType() {
        return authorizationGrantType;
    }

    public Authentication getClientPrincipal() {
        return clientPrincipal;
    }

    /**
     * Returns the requested scope(s).
     *
     * @return the requested scope(s), or an empty {@code Set} if not available
     */
    public Set<String> getScopes() {
        return scopes;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }
}
