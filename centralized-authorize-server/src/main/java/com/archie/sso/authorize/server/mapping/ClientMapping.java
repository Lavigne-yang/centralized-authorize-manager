package com.archie.sso.authorize.server.mapping;

import java.util.ArrayList;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.springframework.util.StringUtils;

import com.archie.sso.authorize.common.dto.Client;
import com.archie.sso.authorize.server.entity.ClientEntity;

/**
 * @author lavyoung1325
 */
@Mapper(componentModel = "spring", imports = {StringUtils.class, ArrayList.class})
public interface ClientMapping {

    @Mapping(expression = "java(StringUtils.collectionToCommaDelimitedString(client.getClientAuthenticationMethods())"
            + ")", target = "clientAuthenticationMethods")
    @Mapping(expression = "java(StringUtils.collectionToCommaDelimitedString(client.getAuthorizationGrantTypes()))",
            target = "authorizationGrantTypes")
    @Mapping(expression = "java(StringUtils.collectionToCommaDelimitedString(client.getRedirectUris()))", target =
            "redirectUris")
    @Mapping(expression = "java(StringUtils.collectionToCommaDelimitedString(client.getPostLogoutRedirectUris()))",
            target = "postLogoutRedirectUris")
    @Mapping(expression = "java(StringUtils.collectionToCommaDelimitedString(client.getScopes()))", target = "scopes")
    @Mapping(expression = "java(StringUtils.collectionToCommaDelimitedString(client.getClientSettings()))", target =
            "clientSettings")
    @Mapping(expression = "java(StringUtils.collectionToCommaDelimitedString(client.getTokenSettings()))", target =
            "tokenSettings")
    ClientEntity toEntity(Client client);


    @Mapping(expression = "java(new ArrayList<>(StringUtils.commaDelimitedListToSet(entity"
            + ".getClientAuthenticationMethods())))", target = "clientAuthenticationMethods")
    @Mapping(expression = "java(new ArrayList<>(StringUtils.commaDelimitedListToSet(entity.getAuthorizationGrantTypes"
            + "())))", target = "authorizationGrantTypes")
    @Mapping(expression = "java(new ArrayList<>(StringUtils.commaDelimitedListToSet(entity.getRedirectUris())))",
            target = "redirectUris")
    @Mapping(expression = "java(new ArrayList<>(StringUtils.commaDelimitedListToSet(entity.getPostLogoutRedirectUris"
            + "())))", target = "postLogoutRedirectUris")
    @Mapping(expression = "java(new ArrayList<>(StringUtils.commaDelimitedListToSet(entity.getScopes())))", target =
            "scopes")
    @Mapping(expression = "java(new ArrayList<>(StringUtils.commaDelimitedListToSet(entity.getClientSettings())))",
            target = "clientSettings")
    @Mapping(expression = "java(new ArrayList<>(StringUtils.commaDelimitedListToSet(entity.getTokenSettings())))",
            target = "tokenSettings")
    Client toVo(ClientEntity entity);
}
