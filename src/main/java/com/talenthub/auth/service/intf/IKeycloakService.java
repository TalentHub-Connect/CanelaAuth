package com.talenthub.auth.service.intf;


import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.request.UserRequest;
import com.talenthub.auth.dto.response.TokenResponse;
import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;

import java.util.List;


public interface IKeycloakService {
    TokenResponse getAccessToken(AuthenticationRequest request) throws ErrorKeycloakServiceException;
    ResponseEntity<?> forgotPassword(String username);
    boolean deleteAccount(String userId);
    ResponseEntity<?> createUserWithRole(UserRequest user, String role);
    void emailVerification(String userId);
    UserRepresentation mapUserRep(UserRequest user);
    void changeUserRoles(String username, List<String> newRoleNames) throws ErrorKeycloakServiceException;
}
