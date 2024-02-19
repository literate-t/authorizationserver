package io.oauth2.authorizationserver.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class OAuth2AuthorizationController {

  private final OAuth2AuthorizationService oAuth2AuthorizationService;

  @GetMapping("/auth")
  public OAuth2Authorization oAuth2Authorization(String accessToken) {
    return oAuth2AuthorizationService.findByToken(accessToken,
        OAuth2TokenType.ACCESS_TOKEN);
  }
}
