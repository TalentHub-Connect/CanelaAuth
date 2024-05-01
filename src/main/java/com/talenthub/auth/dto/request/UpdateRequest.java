package com.talenthub.auth.dto.request;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class UpdateRequest {
    public String email;
    public String FirstName;
    public String LastName;
}
