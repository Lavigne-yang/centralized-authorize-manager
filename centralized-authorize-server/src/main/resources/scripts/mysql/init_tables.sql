INSERT INTO cam.cam_user (user_id, account, username, password, mobile, email, avatar_url, source_from, enable,
                          create_time, update_time)
VALUES ('0683b6cdfde611f00a952d4441425f9f', 'admin', 'admin',
        '$2a$10$A7Crjh/h4KBAtaBUuBVdjuCZ0Uq1.TtkwkVtExNyW2xX9X0A.Zw5O', '18173067573', '3208861258@qq.com', NULL, 1, 1,
        1739263410266, 1739263410266);

insert into cam.cam_oauth2_registered_client (id, client_id, client_id_issued_at, client_secret,
                                              client_secret_expires_at, client_name, client_authentication_methods,
                                              authorization_grant_types, redirect_uris, post_logout_redirect_uris,
                                              scopes, client_settings, token_settings)
values ('337e2eba78eba8e244fd1e248886ddad', 'cam', '2025-03-15 14:52:12',
        '$2a$10$AVt2Z4MiDJ41reKr19.1TOuq.jl7frvn8OytdGkzwMGnGuXvNcs5W', '3025-09-15 14:52:12',
        '337e2eba78eba8e244fd1e248886ddad', 'client_secret_post,client_secret_jwt,client_secret_basic',
        'refresh_token,client_credentials,authorization_code', 'https://www.baidu.com', 'http://127.0.0.1:8000/',
        'openid,profile',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":true}',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.x509-certificate-bound-access-tokens":false,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"reference"},"settings.token.refresh-token-time-to-live":["java.time.Duration",2592000.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}');