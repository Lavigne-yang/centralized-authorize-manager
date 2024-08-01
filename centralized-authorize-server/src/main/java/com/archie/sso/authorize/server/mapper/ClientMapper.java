package com.archie.sso.authorize.server.mapper;


import com.archie.sso.authorize.server.entity.ClientEntity;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ClientMapper extends BaseMapper<ClientEntity> {
}
