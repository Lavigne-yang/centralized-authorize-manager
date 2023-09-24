package com.inge.sso.authorize.server;

import com.baomidou.mybatisplus.generator.FastAutoGenerator;
import com.baomidou.mybatisplus.generator.config.OutputFile;
import com.baomidou.mybatisplus.generator.engine.FreemarkerTemplateEngine;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.*;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class ServerAuthTest {

    private static final String CLIENT_ID = "CAM";

    private static final String CLIENT_SECRET = "secret";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void performTokenRequestWhenValidClientCredentialsThenOk() throws Exception {
        // @formatter:off
        this.mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "client_credentials")
                        .param("scope", "profile")
                        .with(basicAuth(CLIENT_ID, CLIENT_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isString())
                .andExpect(jsonPath("$.expires_in").isNumber())
                .andExpect(jsonPath("$.scope").value("profile"))
                .andExpect(jsonPath("$.token_type").value("Bearer"));
        // @formatter:on
    }


    /**
     * 无授权客户端
     *
     * @throws Exception
     */
    @Test
    void performTokenRequestWhenInvalidClientCredentialsThenUnauthorized() throws Exception {
        // @formatter:off
        this.mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "client_credentials")
                        .param("scope", "cam:read")
                        .with(basicAuth("bad", "password")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
        // @formatter:on
    }

    /**
     * Test case to perform an introspection request with a valid token and expect an OK response.
     *
     * @throws Exception if an error occurs during the test
     */

    @Test
    void performIntrospectionRequestWhenValidTokenThenOk() throws Exception {
        // @formatter:off
        this.mockMvc.perform(post("/oauth2/introspect")
                        .param("token", getAccessToken())
                        .with(basicAuth(CLIENT_ID, CLIENT_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value("true"))
                .andExpect(jsonPath("$.aud[0]").value(CLIENT_ID))
                .andExpect(jsonPath("$.client_id").value(CLIENT_ID))
                .andExpect(jsonPath("$.exp").isNumber())
                .andExpect(jsonPath("$.iat").isNumber())
                .andExpect(jsonPath("$.iss").value("http://localhost"))
                .andExpect(jsonPath("$.nbf").isNumber())
                .andExpect(jsonPath("$.scope").value("cam:read"))
                .andExpect(jsonPath("$.sub").value(CLIENT_ID))
                .andExpect(jsonPath("$.token_type").value("Bearer"));
        // @formatter:on
    }


    private String getAccessToken() throws Exception {
        // @formatter:off
        MvcResult mvcResult = this.mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "client_credentials")
                        .param("scope", "cam:read")
                        .with(basicAuth(CLIENT_ID, CLIENT_SECRET)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andReturn();
        // @formatter:on

        String tokenResponseJson = mvcResult.getResponse().getContentAsString();
        Map<String, Object> tokenResponse = this.objectMapper.readValue(tokenResponseJson, new TypeReference<Map<String, Object>>() {
        });

        return tokenResponse.get("access_token").toString();
    }


    /**
     * Creates a BasicAuthenticationRequestPostProcessor with the given username and password.
     *
     * @param username The username for authentication.
     * @param password The password for authentication.
     * @return A BasicAuthenticationRequestPostProcessor object.
     */

    private static BasicAuthenticationRequestPostProcessor basicAuth(String username, String password) {
        return new BasicAuthenticationRequestPostProcessor(username, password);
    }

    private static final class BasicAuthenticationRequestPostProcessor implements RequestPostProcessor {

        private final String username;

        private final String password;

        private BasicAuthenticationRequestPostProcessor(String username, String password) {
            this.username = username;
            this.password = password;
        }

        /**
         * Adds basic authentication headers to the request.
         *
         * @param request The original request object.
         * @return The modified request object with basic authentication headers.
         */
        @Override
        public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
            HttpHeaders headers = new HttpHeaders();
            headers.setBasicAuth(this.username, this.password);
            request.addHeader("Authorization", Objects.requireNonNull(headers.getFirst("Authorization")));
            return request;
        }

    }

    @Test
    public void test() {
        System.out.println("start...");
        FastAutoGenerator.create("jdbc:mysql://192.168.3.100:3306/cam?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=UTC", "root", "123456")
                // 全局配置
                .globalConfig((scanner, builder) -> builder.author(scanner.apply("lavyoung1325"))
                        .outputDir("F://tmp")
                )
                // 包配置
                .packageConfig((scanner, builder) -> builder.parent(scanner.apply("com.inge.sso.authorize.server"))
                        .pathInfo(Collections.singletonMap(OutputFile.mapper, "F://tmp")))
                // 策略配置
                .strategyConfig((scanner, builder) -> builder.addInclude(getTables(scanner.apply("cam_user,cam_system_authority,cam_role_authority," +
                                "cam_role,cam_user,role")))
                        .addTablePrefix("cam_")
                        .mapperBuilder().enableBaseResultMap().enableBaseColumnList().enableFileOverride()
                        .controllerBuilder().enableRestStyle()
                        .entityBuilder().enableLombok()
                        .build())
                .templateEngine(new FreemarkerTemplateEngine())
                .execute();
        System.out.println("end...");
    }

    protected static List<String> getTables(String tables) {
        return "all".equals(tables) ? Collections.emptyList() : Arrays.asList(tables.split(","));
    }
}
