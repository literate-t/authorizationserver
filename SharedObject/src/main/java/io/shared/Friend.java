package io.shared;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
@AllArgsConstructor
public class Friend {
  public Friend() {}

  private String name;
  private int age;
  private String gender;
}
