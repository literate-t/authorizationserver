package io.oauth2.authorizationserver.config;

import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
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
public class AuthorizationServerConfig2 {

  // 이 부분을 config1이랑 중복 설정이 되게 하고 
  // http의 주소 해시값을 보니까 다른 인스턴스다
  // HttpSecurity는 @Scope("prototype")이기 때문이다
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    return http.build();
  }

  // Required in configuration
  @Bean
  public ProviderSettings providerSettings() {
    // 인가서버 정보는 디폴트가 있을 수 없다
    // 넣어주지 않으면 요청 URL에서 issuer를 추출한다
    return ProviderSettings.builder().issuer("http://localhost:9000").build();
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
