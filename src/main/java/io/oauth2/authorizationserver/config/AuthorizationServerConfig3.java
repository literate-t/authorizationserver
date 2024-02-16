package io.oauth2.authorizationserver.config;

import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationServerConfig3 {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer<>();

    http.apply(authorizationServerConfigurer);

    // authorizationServerConfigurer에 여러 커스텀 설정을 추가할 수 있다

    return http.build();
  }
  @Bean
  public ProviderSettings providerSettings() {
    return ProviderSettings.builder().issuer("http://localhost:9000").build(); // 인가서버 위치
  }

  @Bean
  public RegisteredClientRepository repository() {
    RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("oauth2-client-app")
        .clientSecret("{noop}secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .redirectUri("http://127.0.0.1:8081")
        .scope(OidcScopes.OPENID)
        .scope("message.read")
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .build();

    InMemoryRegisteredClientRepository registeredClientRepository = new InMemoryRegisteredClientRepository(
        client);

    return registeredClientRepository;
  }
}
