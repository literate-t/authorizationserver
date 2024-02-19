package io.oauth2.resourceserverphoto.config;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class OAuth2ResourceServer {


  @Bean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }
}
