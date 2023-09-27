-- 授权客户端注册信息
CREATE TABLE cam_oauth2_registered_client
(
    id                            varchar(100)                            NOT NULL,
    client_id                     varchar(100)                            NOT NULL,
    client_id_issued_at           timestamp     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamp     DEFAULT NULL,
    client_name                   varchar(200)                            NOT NULL,
    client_authentication_methods varchar(1000)                           NOT NULL,
    authorization_grant_types     varchar(1000)                           NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000)                           NOT NULL,
    client_settings               varchar(2000)                           NOT NULL,
    token_settings                varchar(2000)                           NOT NULL,
    PRIMARY KEY (id)
);

-- 授权确认数据
CREATE TABLE cam_oauth2_authorization_consent
(
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);


/*
IMPORTANT:
    If using PostgreSQL, update ALL columns defined with 'blob' to 'text',
    as PostgreSQL does not support the 'blob' data type.
 客户端授权信息
*/
CREATE TABLE cam_oauth2_authorization
(
    id                            varchar(100) NOT NULL,
    registered_client_id          varchar(100) NOT NULL,
    principal_name                varchar(200) NOT NULL,
    authorization_grant_type      varchar(100) NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    blob          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      blob          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   blob          DEFAULT NULL,
    access_token_value            blob          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         blob          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           blob          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        blob          DEFAULT NULL,
    refresh_token_value           blob          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        blob          DEFAULT NULL,
    PRIMARY KEY (id)
);


-- auto-generated definition
create table cam_system_authority
(
    id             varchar(100)      not null comment '菜单ID'
        primary key,
    menu_name      varchar(150)      not null comment '菜单名称',
    menu_parent_id varchar(100) null comment '父菜单ID',
    path           varchar(255) null comment '图标路径',
    authority      varchar(150) null comment '权限',
    sort           int     default 0 not null comment '排序',
    deleted        tinyint default 0 not null comment '是否删除 否：0，是：1',
    createTime     bigint            not null comment '创建时间',
    updateTime     bigint            not null comment '修改时间'
) comment '系统菜单权限';

create table cam_role_authority
(
    id           varchar(100) not null comment 'id',
    role_id      varchar(100) not null comment '角色id',
    authority_id varchar(100) not null comment '权限id',
    constraint cam_role_authority_pk
        primary key (id)
) comment '角色权限表';

create table cam_role
(
    id          varchar(100)      not null comment '角色id',
    role_name   varchar(150)      not null comment '角色名称',
    deleted     tinyint default 0 not null comment '是否删除',
    sort        int     default 0 not null comment '排序',
    create_time bigint            not null comment '创建时间',
    update_time bigint            not null comment '修改时间',
    constraint cam_role_pk
        primary key (id)
) comment '角色';

-- auto-generated definition
create table cam_user
(
    user_id     varchar(100)      not null comment '用户id'
        primary key,
    account     varchar(150)      not null comment '账户',
    username    varchar(150)      not null comment '用户名',
    password    varchar(200)      not null comment '密码',
    mobile      varchar(30) null comment '手机号',
    email       varchar(200)      not null comment '邮箱',
    avatar_url  varchar(500) null comment '头像地址',
    source_from tinyint default 1 not null comment '用户来源',
    enable      tinyint(1) default 1 not null comment '是否启用',
    create_time bigint            not null comment '创建时间',
    update_time bigint            not null comment '更新时间'
) comment '用户数据';

-- auto-generated definition
create table cam_user_role
(
    id      varchar(100) not null comment 'id'
        primary key,
    user_id varchar(100) not null comment '用户id',
    role_id varchar(100) not null comment '角色id'
) comment '用户角色';


