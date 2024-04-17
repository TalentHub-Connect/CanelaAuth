package com.talenthub.auth.service.intf;

import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import org.keycloak.admin.client.Keycloak;

import java.util.List;

public interface IKeycloakRoleService {
    Keycloak getKeycloakInstance();
    void createRole(String roleName) throws ErrorKeycloakServiceException;
    void deleteRole(String roleName) throws ErrorKeycloakServiceException;
    void changeUserRoles(String username, List<String> newRoleNames) throws ErrorKeycloakServiceException;
    void deleteUserRoles(String username, List<String> roleNames) throws ErrorKeycloakServiceException;
    List<String> getUserRoles(String username) throws ErrorKeycloakServiceException;
    void addRoles(String username, List<String> roleNames) throws ErrorKeycloakServiceException;
}
