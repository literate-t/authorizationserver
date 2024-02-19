package io.oauth2.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {
  @Bean
  public SecurityFilterChain securityConfig(HttpSecurity http) throws Exception {
    http.authorizeRequests(registry -> registry.anyRequest().authenticated());
    http.formLogin(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user = User.withUsername("user")
        .password("{noop}1234")
        .authorities("ROLE_USER")
        .build();

    return new InMemoryUserDetailsManager(user);
  }

  // Default로 사용되는 InMemory 방식이지만
  // 컨트롤러에서 빈을 주입받기 위해 사용자 정의를 다시 해줌
  @Bean
  public OAuth2AuthorizationService oAuth2AuthorizationService() {
    return new InMemoryOAuth2AuthorizationService();
  }
}
