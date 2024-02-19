package io.oauth2.resourceserverfriend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Component
public class OAuth2ResourceServer {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    http.authorizeRequests(
        registry -> registry.antMatchers("/friends").access("hasAuthority('SCOPE_friend')")
            .anyRequest().authenticated());

    http.oauth2ResourceServer().jwt();
    http.cors().configurationSource(corsConfigurationSource());

    return http.build();
  }

  private CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration corsConfiguration = new CorsConfiguration();
    corsConfiguration.addAllowedHeader("*");
    corsConfiguration.addAllowedOrigin("*");
    corsConfiguration.addAllowedMethod("*");
    corsConfiguration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfiguration);

    return source;
  }
}
