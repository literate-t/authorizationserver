package io.oauth2.oauth2client.controller;

import io.shared.AccessToken;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequiredArgsConstructor
public class RestApiController {

  private final RestTemplate restTemplate;
  private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
  private final OAuth2AuthorizedClientService auth2AuthorizedClientService;

  @GetMapping("/token")
  public OAuth2AccessToken accessToken(@RegisteredOAuth2AuthorizedClient("springoauth2")
      OAuth2AuthorizedClient authorizedClient) {
    return authorizedClient.getAccessToken();
  }

  @GetMapping("/tokenExpire")
  public Map<String, Object> tokenExpired(AccessToken accessToken) {
    HttpHeaders header = new HttpHeaders();
    header.add("Authorization", " Bearer " + accessToken.getToken());
    HttpEntity<?> entity = new HttpEntity<>(header);
    String url = "http://localhost:8082/tokenExpire";

    ResponseEntity<Map<String, Object>> response = restTemplate.exchange(url, HttpMethod.GET, entity, new ParameterizedTypeReference<>() {});

    return response.getBody();
  }

  @GetMapping("/newAccessToken")
  public OAuth2AccessToken newAccessToken(OAuth2AuthenticationToken authentication,
      HttpServletRequest request, HttpServletResponse response) {

    OAuth2AuthorizedClient authorizedClient = auth2AuthorizedClientService.loadAuthorizedClient(
        authentication.getAuthorizedClientRegistrationId(), authentication.getName());

    if (null != authorizedClient && null != authorizedClient.getRefreshToken()) {
      ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(
              authorizedClient.getClientRegistration())
          .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
          .build();

      OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(clientRegistration,
          authorizedClient.getPrincipalName(),
          authorizedClient.getAccessToken(), authorizedClient.getRefreshToken());

      OAuth2AuthorizeRequest oAuth2AuthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(
              oAuth2AuthorizedClient)
          .principal(authentication)
          .attribute(HttpServletRequest.class.getName(), request)
          .attribute(HttpServletResponse.class.getName(), response)
          .build();

      authorizedClient = oAuth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
    }

    return authorizedClient.getAccessToken();
  }
}
