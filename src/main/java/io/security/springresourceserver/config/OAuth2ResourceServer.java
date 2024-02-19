package io.security.springresourceserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
public class OAuth2ResourceServer {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(registry -> registry.anyRequest().authenticated());


    // spring.security.oauth2.resourceserver.jwt.jwk-set-uri 가 설정되어 있으면
    // jwtDecoder bean을 자동 주입해준다
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // jwt decoder를 실행할 수 있는 api

    return http.build();
  }

//  @Bean
//  public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
//
//    http.authorizeRequests(
//        registry -> registry.anyRequest().authenticated());
//    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
//
//    return http.build();
//  }

//  @Bean
//  public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties properties) {
//    Opaquetoken token = properties.getOpaquetoken();
//
//    return new NimbusOpaqueTokenIntrospector(token.getIntrospectionUri(), token.getClientId(),
//        token.getClientSecret());
//  }

}
