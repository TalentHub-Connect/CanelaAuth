package com.talenthub.auth.dto.request;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class UserRequest {
    private String FirstName;
    private String LastName;
    private String email;
}
