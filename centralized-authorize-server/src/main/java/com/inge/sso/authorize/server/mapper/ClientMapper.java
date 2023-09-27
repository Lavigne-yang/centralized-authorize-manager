package com.inge.sso.authorize.server.mapper;


import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.inge.sso.authorize.server.entity.ClientEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ClientMapper extends BaseMapper<ClientEntity> {
}
