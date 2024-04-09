package com.talenthub.auth.dto.response;

import lombok.*;

import java.math.BigInteger;
import java.util.Set;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponse {
    private String nombres;
    private String correo;
    private String username;
}
