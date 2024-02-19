package io.oauth2.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationServerConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

//    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer<>();
    RequestMatcher endpointsMatcher = authorizationServerConfigurer
        .getEndpointsMatcher();

    http
        .requestMatcher(endpointsMatcher)
        .authorizeRequests(authorizeRequests ->
            authorizeRequests.anyRequest().authenticated()
        )
        .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
        .apply(authorizationServerConfigurer);

    http.exceptionHandling(
        config -> config.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

    // 토큰 검증 및 인증 처리까지
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

    return http.build();
  }
}
