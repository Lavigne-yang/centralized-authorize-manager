package com.inge.sso.authorize.server.config;

import com.inge.sso.authorize.server.federation.FederatedIdentityAuthenticationFailureHandler;
import com.inge.sso.authorize.server.federation.FederatedIdentityAuthenticationSuccessHandler;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * @author lavyoung1325
 */
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(DefaultSecurityConfig.class);

    /**
     * Spring Security的过滤器链，用于Spring Security的身份认证。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers().permitAll()
//                        .anyRequest().authenticated()
//                )
//                // Form login handles the redirect to the login page from the
//                // authorization server filter chain
//                .formLogin(Customizer.withDefaults())
//                .oauth2Login(oauthLogin ->
//                        oauthLogin.loginPage("/login")
//                                .successHandler(authenticationSuccessHandler())
//                );
        http.formLogin(form ->
                        form
                                .loginProcessingUrl("/login")
                                .successHandler(authenticationSuccessHandler())
                                .defaultSuccessUrl("/activated", false)
                                .failureForwardUrl("/error")
                                .failureHandler(authenticationFailureHandler())
                )
                .authorizeHttpRequests(authorize -> authorize
                        .mvcMatchers("/assets/**", "/webjars/**", "/login").permitAll()
                        .antMatchers("/", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .addLogoutHandler(((request, response, authentication) -> {
                            logger.info("request method: {}", request.getMethod());
                            logger.info("{} logout success...", authentication.getName());
                        }))
                        .deleteCookies()
                );

        return http.build();
    }

    /**
     * 授權成功處理
     *
     * @return
     */
    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new FederatedIdentityAuthenticationSuccessHandler();
    }

    private AuthenticationFailureHandler authenticationFailureHandler() {
        return new FederatedIdentityAuthenticationFailureHandler();
    }

    /**
     * 盐值加密
     *
     * @return
     */
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user1")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

}
