package com.archie.sso.authorize.server.mapping;

import com.archie.sso.authorize.common.dto.Client;
import com.archie.sso.authorize.server.entity.ClientEntity;
import org.mapstruct.Mapper;

/**
 * @author lavyoung1325
 */
@Mapper(componentModel = "spring")
public interface ClientMapping {
    
    
    ClientEntity toEntity(Client client);
}
