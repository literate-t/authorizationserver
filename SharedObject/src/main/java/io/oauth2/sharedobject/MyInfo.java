package io.oauth2.sharedobject;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MyInfo {
  private List<Friend> friends;
  private List<Photo> photos;
}
