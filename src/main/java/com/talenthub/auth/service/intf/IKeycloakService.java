package com.talenthub.auth.service.intf;


import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.response.TokenResponse;
import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import org.springframework.http.ResponseEntity;

public interface IKeycloakService {
    TokenResponse getAccessToken(AuthenticationRequest request) throws ErrorKeycloakServiceException;
    ResponseEntity<?> forgotPassword(String username);
    boolean deleteAccount(String userId);

}
