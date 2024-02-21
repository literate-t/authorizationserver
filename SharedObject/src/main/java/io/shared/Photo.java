package io.shared;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class Photo {

  private String id;
  private String title;
  private String description;
}
