package io.oauth2.resourceserverphoto.controller;

import io.oauth2.resourceserverphoto.service.PhotoService;
import io.oauth2.sharedobject.Photo;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

  @GetMapping("/photos")
  public List<Photo> photos() {
    Photo photo1 = PhotoService.getBuild("1", "Album1 title", "Album1 desc");
    Photo photo2 = PhotoService.getBuild("2", "Album2 title", "Album2 desc");

    return List.of(photo1, photo2);
  }

  @GetMapping("/tokenExpire")
  public Map<String, Object> tokenExpire() {
    Map<String, Object> result = new HashMap<>();
    result.put("error", new OAuth2Error("invalid token", "token is expired", null));

    return result;
  }
}
