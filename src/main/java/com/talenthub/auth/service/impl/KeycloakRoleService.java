package com.talenthub.auth.service.impl;

import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import com.talenthub.auth.security.KeycloakSecurityUtil;
import com.talenthub.auth.service.intf.IKeycloakRoleService;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class KeycloakRoleService implements IKeycloakRoleService {
    @Value("${realm}")
    private  String realm;
    private final KeycloakSecurityUtil keycloakUtil;

    @Autowired
    public KeycloakRoleService(KeycloakSecurityUtil keycloakUtil) {
        this.keycloakUtil = keycloakUtil;
    }

    @Override
    public Keycloak getKeycloakInstance() {
        return keycloakUtil.getKeycloakInstance();
    }

    public UserResource getUserResource(String username) {
        Keycloak keycloak = getKeycloakInstance();
        String userId = keycloak.realm(realm).users().search(username).get(0).getId();
        return keycloak.realm(realm).users().get(userId);
    }

    @Override
    public void createRole(String roleName) throws ErrorKeycloakServiceException {
        Keycloak keycloak = getKeycloakInstance();
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        try {
            keycloak.realm(realm).roles().create(role);
        } catch (Exception e) {
            throw new ErrorKeycloakServiceException("Failed to create role: " + roleName, HttpStatus.BAD_REQUEST.value());
        }
    }


    @Override
    public void deleteRole(String roleName) throws ErrorKeycloakServiceException {
        Keycloak keycloak = getKeycloakInstance();
        try {
            keycloak.realm(realm).roles().deleteRole(roleName);
        } catch (Exception e) {
            throw new ErrorKeycloakServiceException("Failed to delete role: " + roleName, HttpStatus.NOT_FOUND.value());
        }
    }


    @Override
    public void changeUserRoles(String username, List<String> newRoleNames) throws ErrorKeycloakServiceException {
        try {
            UserResource userResource = getUserResource(username);
            RoleMappingResource roleMappingResource = userResource.roles();
            removeAllRoles(roleMappingResource);
            addRoles(username, newRoleNames);
        } catch (Exception e) {
            throw new ErrorKeycloakServiceException(e.getMessage(), HttpStatus.NOT_FOUND.value());
        }
    }

    private void removeAllRoles(RoleMappingResource roleMappingResource) {
        roleMappingResource.realmLevel().remove(roleMappingResource.realmLevel().listAll());
    }

    @Override
    public void deleteUserRoles(String username, List<String> roleNames) throws ErrorKeycloakServiceException {
        try {
            UserResource userResource = getUserResource(username);
            RoleMappingResource roleMappingResource = userResource.roles();
            removeAllRoles(roleMappingResource);
            removeRoles(username, roleNames);
        } catch (Exception e) {
            throw new ErrorKeycloakServiceException(e.getMessage(), HttpStatus.NOT_FOUND.value());
        }
    }

    @Override
    public List<String> getUserRoles(String username) throws ErrorKeycloakServiceException {
        try {
            UserResource userResource = getUserResource(username);
            return userResource.roles().realmLevel().listEffective().stream()
                    .map(RoleRepresentation::getName)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            throw new ErrorKeycloakServiceException("Failed to fetch user roles for: " + username, HttpStatus.NOT_FOUND.value());
        }
    }

    @Override
    public void addRoles(String username, List<String> roleNames) throws ErrorKeycloakServiceException {
        UserResource userResource = getUserResource(username);
        RoleMappingResource roleMappingResource = userResource.roles();
        List<RoleRepresentation> rolesToAdd = roleNames.stream()
                .map(roleName -> getKeycloakInstance().realm(realm).roles().get(roleName).toRepresentation())
                .collect(Collectors.toList());
        try {
            roleMappingResource.realmLevel().add(rolesToAdd);
        } catch (Exception e) {
            throw new ErrorKeycloakServiceException("Failed to add roles to user: " + username, HttpStatus.BAD_REQUEST.value());
        }
    }


    private void removeRoles(String username, List<String> roleNames) {
        List<RoleRepresentation> rolesToRemove = roleNames.stream()
                .map(roleName -> getKeycloakInstance().realm(realm).roles().get(roleName).toRepresentation())
                .collect(Collectors.toList());
        getUserResource(username).roles().realmLevel().remove(rolesToRemove);
    }

}
