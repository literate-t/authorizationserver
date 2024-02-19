package io.oauth2.resourceserverphoto.service;

import io.oauth2.sharedobject.Photo;
import org.springframework.stereotype.Service;

@Service
public class PhotoService {
  public static Photo getBuild(String id, String title, String description) {
    return Photo.builder()
        .id(id)
        .title(title)
        .description(description)
        .build();
  }
}
