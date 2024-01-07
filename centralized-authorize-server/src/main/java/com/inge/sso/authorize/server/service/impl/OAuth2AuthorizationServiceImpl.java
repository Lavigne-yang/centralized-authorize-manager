package com.inge.sso.authorize.server.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.inge.sso.authorize.server.entity.OAuth2AuthorizationEntity;
import com.inge.sso.authorize.server.mapper.OAuth2AuthorizationMapper;
import com.inge.sso.authorize.server.service.AuthorizationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.util.*;

/**
 * Created by IntelliJ IDEA
 *
 * @author : lavyoung1325
 * @create 2023/9/28
 */
@Service
public class OAuth2AuthorizationServiceImpl extends ServiceImpl<OAuth2AuthorizationMapper, OAuth2AuthorizationEntity> implements AuthorizationService, OAuth2AuthorizationService {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationServiceImpl.class);

    @Resource
    private RegisteredClientRepository registeredClientRepository;

    @Resource
    private OAuth2AuthorizationMapper oAuth2AuthorizationMapper;

    @Resource
    private ObjectMapper objectMapper;


    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2Authorization auth2Authorization = findById(authorization.getId());
        if (auth2Authorization == null) {
            insertAuthorization(authorization);
        } else {
            updateAuthorization(authorization);
        }
    }

    private void updateAuthorization(OAuth2Authorization authorization) {
        this.baseMapper.updateById(dataToRow(authorization));
    }

    private void insertAuthorization(OAuth2Authorization authorization) {
        this.baseMapper.insert(dataToRow(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        logger.info("remove authorization: name: {}, ", authorization.getPrincipalName());
        oAuth2AuthorizationMapper.deleteById(authorization.getId());
    }

    @Override
    @Nullable
    public OAuth2Authorization findById(String id) {
        Assert.notNull(id, "id  cannot be null");
        return findBy(Collections.singletonList(oAuth2AuthorizationMapper.selectById(id)));
    }


    @Override
    @Nullable
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        if (tokenType == null) {
            List<OAuth2AuthorizationEntity> sqlData = this.baseMapper.selectList(Wrappers.lambdaQuery(OAuth2AuthorizationEntity.class)
                    .eq(OAuth2AuthorizationEntity::getState, token)
                    .or()
                    .eq(OAuth2AuthorizationEntity::getAuthorizationCodeValue, token)
                    .or()
                    .eq(OAuth2AuthorizationEntity::getAccessTokenValue, token)
                    .or()
                    .eq(OAuth2AuthorizationEntity::getRefreshTokenValue, token)
            );
            return findBy(sqlData);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            List<OAuth2AuthorizationEntity> sqlData = this.baseMapper.selectList(Wrappers.lambdaQuery(OAuth2AuthorizationEntity.class)
                    .eq(OAuth2AuthorizationEntity::getState, token));
            return findBy(sqlData);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            List<OAuth2AuthorizationEntity> sqlData = this.baseMapper.selectList(Wrappers.lambdaQuery(OAuth2AuthorizationEntity.class)
                    .eq(OAuth2AuthorizationEntity::getAuthorizationCodeValue, token));
            return findBy(sqlData);
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            List<OAuth2AuthorizationEntity> sqlData = this.baseMapper.selectList(Wrappers.lambdaQuery(OAuth2AuthorizationEntity.class)
                    .eq(OAuth2AuthorizationEntity::getAccessTokenValue, token));
            return findBy(sqlData);
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            List<OAuth2AuthorizationEntity> sqlData = this.baseMapper.selectList(Wrappers.lambdaQuery(OAuth2AuthorizationEntity.class)
                    .eq(OAuth2AuthorizationEntity::getRefreshTokenValue, token));
            return findBy(sqlData);
        }
        return null;
    }

    private OAuth2Authorization findBy(Collection<OAuth2AuthorizationEntity> data) {
        List<OAuth2Authorization> authorizations = mapRow(data);
        return !authorizations.isEmpty() ? authorizations.get(0) : null;
    }

    private List<OAuth2Authorization> mapRow(Collection<OAuth2AuthorizationEntity> data) {
        List<OAuth2Authorization> mapResult = new ArrayList<>();
        data.forEach(item -> {
            String registeredClientId = item.getRegisteredClientId();
            RegisteredClient client = registeredClientRepository.findByClientId(registeredClientId);
            if (client == null) {
                throw new DataRetrievalFailureException(
                        "The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
            }
            OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client);
            Set<String> authorizationScopes = Collections.emptySet();
            if (item.getAuthorizedScopes() != null) {
                authorizationScopes = StringUtils.commaDelimitedListToSet(item.getAuthorizedScopes());
            }
            Map<String, Object> attributes = parseMap(item.getAttributes());
            builder.id(item.getId())
                    .principalName(item.getPrincipalName())
                    .authorizationGrantType(new AuthorizationGrantType(item.getAuthorizationGrantType()))
                    .authorizedScopes(authorizationScopes)
                    .attributes(attrs -> attrs.putAll(attributes));
            if (StringUtils.hasText(item.getState())) {
                builder.attribute(OAuth2ParameterNames.STATE, item.getState());
            }
            if (StringUtils.hasText(item.getAuthorizationCodeValue())) {
                Map<String, Object> auhorizationCodeMetadataMap = parseMap(item.getAuthorizationCodeMetadata());
                OAuth2AuthorizationCode authorizationCodeMetadata = new OAuth2AuthorizationCode(
                        item.getAuthorizationCodeValue(), item.getAuthorizationCodeIssuedAt(), item.getAuthorizationCodeExpiresAt()
                );
                builder.token(authorizationCodeMetadata, metadata -> metadata.putAll(auhorizationCodeMetadataMap));
            }
            if (StringUtils.hasText(item.getAccessTokenValue())) {
                Map<String, Object> accessTokenMetadata = parseMap(item.getAccessTokenMetadata());
                OAuth2AccessToken.TokenType tokenType = null;
                if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(item.getAccessTokenType())) {
                    tokenType = OAuth2AccessToken.TokenType.BEARER;
                }

                Set<String> scopes = Collections.emptySet();
                if (item.getAccessTokenScopes() != null) {
                    scopes = StringUtils.commaDelimitedListToSet(item.getAccessTokenScopes());
                }
                OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, item.getAccessTokenValue(), item.getAccessTokenIssuedAt(), item.getAccessTokenExpiresAt(), scopes);
                builder.token(accessToken, (metadata) -> metadata.putAll(accessTokenMetadata));
            }
            if (StringUtils.hasText(item.getOidcIdTokenValue())) {
                Map<String, Object> oidcTokenMetadata = parseMap(item.getOidcIdTokenMetadata());
                OidcIdToken oidcIdToken = new OidcIdToken(
                        item.getOidcIdTokenValue(), item.getOidcIdTokenIssuedAt(), item.getOidcIdTokenExpiresAt(), (Map<String, Object>) oidcTokenMetadata.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME)
                );
                builder.token(oidcIdToken, metadata -> metadata.putAll(oidcTokenMetadata));
            }
            if (StringUtils.hasText(item.getRefreshTokenValue())) {
                Map<String, Object> refreshTokenMetadata = parseMap(item.getRefreshTokenMetadata());
                OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                        item.getRefreshTokenValue(), item.getRefreshTokenIssuedAt(), item.getRefreshTokenExpiresAt());
                builder.token(refreshToken, metadata -> metadata.putAll(refreshTokenMetadata));
            }
            mapResult.add(builder.build());
        });
        return mapResult;
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }


    private OAuth2AuthorizationEntity dataToRow(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = new OAuth2AuthorizationEntity();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
        if (!CollectionUtils.isEmpty(authorization.getAuthorizedScopes())) {
            entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ","));
        }
        String attributes = writeMap(authorization.getAttributes());
        entity.setAttributes(attributes);
        String authorizationState = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (StringUtils.hasText(authorizationState)) {
            entity.setState(attributes);
        }
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            String tokenValue = authorizationCode.getToken().getTokenValue();
            if (tokenValue != null) {
                entity.setAuthorizationCodeValue(tokenValue);
            }
            if (authorizationCode.getToken().getIssuedAt() != null) {
                entity.setAuthorizationCodeIssuedAt(authorizationCode.getToken().getIssuedAt());
            }
            if (authorizationCode.getToken().getExpiresAt() != null) {
                entity.setAuthorizationCodeExpiresAt(authorizationCode.getToken().getExpiresAt());
            }
            if (authorizationCode.getMetadata() != null) {
                entity.setAuthorizationCodeMetadata(writeMap(authorizationCode.getMetadata()));
            }
        }
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            String tokenValue = accessToken.getToken().getTokenValue();
            if (tokenValue != null) {
                entity.setAccessTokenValue(tokenValue);
            }
            if (accessToken.getToken().getIssuedAt() != null) {
                entity.setAccessTokenIssuedAt(accessToken.getToken().getIssuedAt());
            }
            if (accessToken.getToken().getExpiresAt() != null) {
                entity.setAccessTokenExpiresAt(accessToken.getToken().getExpiresAt());
            }
            if (accessToken.getMetadata() != null) {
                entity.setAccessTokenMetadata(writeMap(accessToken.getMetadata()));
            }
            String accessTokenType = accessToken.getToken().getTokenType().getValue();
            entity.setAccessTokenType(accessTokenType);
            if (!CollectionUtils.isEmpty(accessToken.getToken().getScopes())) {
                String accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ",");
                entity.setAccessTokenScopes(accessTokenScopes);
            }
        }
        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            String tokenValue = oidcIdToken.getToken().getTokenValue();
            if (tokenValue != null) {
                entity.setOidcIdTokenValue(tokenValue);
            }
            if (oidcIdToken.getToken().getIssuedAt() != null) {
                entity.setOidcIdTokenIssuedAt(oidcIdToken.getToken().getIssuedAt());
            }
            if (oidcIdToken.getToken().getExpiresAt() != null) {
                entity.setOidcIdTokenExpiresAt(oidcIdToken.getToken().getExpiresAt());
            }
            if (oidcIdToken.getMetadata() != null) {
                entity.setOidcIdTokenMetadata(writeMap(oidcIdToken.getMetadata()));
            }
        }
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken != null) {
            String tokenValue = refreshToken.getToken().getTokenValue();
            if (tokenValue != null) {
                entity.setRefreshTokenValue(tokenValue);
            }
            if (refreshToken.getToken().getIssuedAt() != null) {
                entity.setRefreshTokenIssuedAt(refreshToken.getToken().getIssuedAt());
            }
            if (refreshToken.getToken().getExpiresAt() != null) {
                entity.setRefreshTokenExpiresAt(refreshToken.getToken().getExpiresAt());
            }
            if (refreshToken.getMetadata() != null) {
                entity.setRefreshTokenMetadata(writeMap(refreshToken.getMetadata()));
            }
        }
        return entity;
    }

    private String writeMap(Map<String, Object> data) {
        try {
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }
}
