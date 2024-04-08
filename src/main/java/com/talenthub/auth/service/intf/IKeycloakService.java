package com.talenthub.auth.service.intf;


import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.response.TokenResponse;
import com.talenthub.auth.exception.ErrorKeycloakServiceException;

public interface IKeycloakService {
    TokenResponse getAccessToken(AuthenticationRequest request) throws ErrorKeycloakServiceException;
}
