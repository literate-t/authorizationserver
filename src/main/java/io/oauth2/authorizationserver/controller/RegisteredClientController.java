package io.oauth2.authorizationserver.controller;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RegisteredClientController {

  private final RegisteredClientRepository repository;

  @GetMapping("/registeredClients")
  public List<RegisteredClient> registeredClientList() {
    RegisteredClient client1 = repository.findByClientId("oauth2-client-app1");
    RegisteredClient client2 = repository.findByClientId("oauth2-client-app2");
    RegisteredClient client3 = repository.findByClientId("oauth2-client-app3");

    return List.of(client1, client2, client3);
  }
}
