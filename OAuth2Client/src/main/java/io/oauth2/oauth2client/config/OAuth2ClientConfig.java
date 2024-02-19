package io.oauth2.oauth2client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class OAuth2ClientConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
        registry -> registry.antMatchers("/", "/photos").permitAll().anyRequest().authenticated());
    http.oauth2Login(config -> config.defaultSuccessUrl("/"));
    http.oauth2Client();

    return http.build();
  }

  @Bean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }

  // OAuth2
  @Bean
  public DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager(
      ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository) {

    OAuth2AuthorizedClientProvider auth2AuthorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .clientCredentials()
            .password()
            .refreshToken()
            .build();

    DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager =
        new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository,
            auth2AuthorizedClientRepository);

    auth2AuthorizedClientManager.setAuthorizedClientProvider(auth2AuthorizedClientProvider);

    return auth2AuthorizedClientManager;
  }
}
