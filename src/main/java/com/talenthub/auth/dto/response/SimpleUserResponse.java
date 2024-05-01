package com.talenthub.auth.dto.response;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SimpleUserResponse {
    public String id;
    public String firstName;
    public String lastName;
    public String username;
    public String email;
}
