package com.talenthub.auth.dto.request;

import lombok.*;

import java.math.BigInteger;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class UserRequest {
    private Integer id;
    private String nombres;
    private String correo;
    private String password;
    private String username;
}
