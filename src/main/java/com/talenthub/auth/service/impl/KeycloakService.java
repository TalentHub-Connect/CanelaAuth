package com.talenthub.auth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.request.UpdateRequest;
import com.talenthub.auth.dto.request.UserRequest;
import com.talenthub.auth.dto.response.TokenResponse;
import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import com.talenthub.auth.security.KeycloakSecurityUtil;
import com.talenthub.auth.service.intf.IKeycloakService;
import com.talenthub.auth.tool.ObjectToUrlEncodedConverter;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;


import java.util.*;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;


/**
 * Class KeycloakService which implements the IKeycloakService interface
 * This class is used to manage the Keycloak service, including the creation of users, the generation of access tokens,
 * the password recovery and the deletion of accounts.
 * @see IKeycloakService
 * @see KeycloakSecurityUtil
 * @see TokenResponse
 * @see ErrorKeycloakServiceException
 * @see AuthenticationRequest
 */

@Service
public class KeycloakService implements IKeycloakService {

    @Value("${authServerUrl}")
    private  String authServerUrl;

    @Value("${realm}")
    private  String realm;

    @Value("${keycloak.resource.client-id}")
    private  String clientId;

    @Value("${grant-type}")
    private  String grantType;

    @Value("${keycloak.credentials.secret}")
    private  String clientSecret;

    private final KeycloakSecurityUtil keycloakUtil;

    @Autowired
    public KeycloakService(KeycloakSecurityUtil keycloakUtil) {
        this.keycloakUtil = keycloakUtil;
    }

    @Override
    public Keycloak getKeycloakInstance() {
        return keycloakUtil.getKeycloakInstance();
    }

    /**
    Método para obtener el token de acceso a partir de las credenciales de un usuario.
    @param request Credenciales del usuario.
    @throws ErrorKeycloakServiceException Excepción en caso de error en el servicio de datos.
    @return TokenResponse con el token de acceso y el rol del usuario.
     */

    @Override
    public TokenResponse getAccessToken(AuthenticationRequest request) throws ErrorKeycloakServiceException {
        // Create the request headers
        try{
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            ObjectMapper objectMapper = new ObjectMapper();
            RestTemplate restTemplate = new RestTemplate();
            restTemplate.getMessageConverters().add(new ObjectToUrlEncodedConverter(objectMapper));
            // Create the request body
            MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("grant_type", grantType);
            requestBody.add("client_id", clientId);
            requestBody.add("client_secret", clientSecret);
            requestBody.add("username", request.getUsername());
            requestBody.add("password", request.getPassword());

            // Create the request entity
            RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity
                    .post(authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                    .headers(headers)
                    .body(requestBody);
            ParameterizedTypeReference<Map<String, Object>> responseType = new ParameterizedTypeReference<>() {};
            ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(requestEntity, responseType);
            Map<String, Object> responseMap = responseEntity.getBody();
            assert responseMap != null;
            String role = getRole(request.getUsername());
            return TokenResponse.builder()
                    .access_token((String) responseMap.get("access_token"))
                    .role(role)
                    .build();
        }catch (HttpClientErrorException e){
            throw new ErrorKeycloakServiceException(e.getMessage(), e.getStatusCode().value());
        }
    }

    public String getRole(String username) {
        Keycloak keycloak = getKeycloakInstance();
        String userId = keycloak.realm(realm).users().search(username).get(0).getId();
        List<RoleRepresentation> roles = keycloak.realm(realm).users().get(userId).roles().realmLevel().listAll();
        return roles.stream().map(RoleRepresentation::getName).collect(Collectors.joining(", "));
    }

    /**
     * Método para crear un usuario con un rol específico en Keycloak.
     * @param user Usuario a crear.
     * @param role Rol del usuario
     * @return ResponseEntity con el usuario creado.
     */

    @Override
    public ResponseEntity<?> createUserWithRole(@RequestBody UserRequest user, String role, String enterprise) {
        String firstName = user.getFirstName().trim().replaceAll("\\s+", "");
        String lastName = user.getLastName().trim().replaceAll("\\s+", "");
        String baseUsername = (firstName + "." + lastName + "@" + enterprise +".com").toLowerCase();

        Keycloak keycloak = getKeycloakInstance();
        String uniqueUsername = generateUniqueUsername(baseUsername, keycloak);
        UserRepresentation userRep = mapUserRep(user);
        userRep.setUsername(uniqueUsername);
        Response res = keycloak.realm(realm).users().create(userRep);

        if (res.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
            UserRepresentation userRepresentation = keycloak.realm(realm).users().search(uniqueUsername).get(0);
            emailVerification(userRepresentation.getId());
            keycloak.realm(realm).users().get(userRepresentation.getId()).resetPassword(mapUserRep(user).getCredentials().get(0));
            String userId = userRepresentation.getId();
            RoleRepresentation roleRep = keycloak.realm(realm).roles().get(role).toRepresentation();
            keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Collections.singletonList(roleRep));
            return ResponseEntity.status(HttpStatus.CREATED).body(user);
        } else {
            String errorMessage = res.readEntity(String.class);
            return ResponseEntity.badRequest().body(errorMessage);
        }
    }

    private String generateUniqueUsername(String baseUsername, Keycloak keycloak) {
        int counter = 1;
        String baseName = baseUsername.substring(0, baseUsername.indexOf("@"));
        String domain = baseUsername.substring(baseUsername.indexOf("@"));

        String candidateUsername = baseUsername;
        while (!keycloak.realm(realm).users().search(candidateUsername).isEmpty()) {
            counter++;
            candidateUsername = baseName + counter + domain;
        }
        return candidateUsername;
    }



    @Override
    public boolean updateUser(String username, UpdateRequest user) {
        Keycloak keycloak = getKeycloakInstance();
        List<UserRepresentation> users = keycloak.realm(realm).users().search(username);
        if (users.isEmpty()) {
            throw new RuntimeException("Usuario not found");
        }
        String userId = users.get(0).getId();
        try {
            UserRepresentation userRep = updateUserMap(user);
            keycloak.realm(realm).users().get(userId).update(userRep);
            return true;
        } catch (NotFoundException e) {
            throw new RuntimeException("Usuario no encontrado: " + username, e);
        } catch (WebApplicationException e) {
            Response response = e.getResponse();
            throw new RuntimeException("fail de la API al update el usuario: HTTP Status " + response.getStatus(), e);
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error while updating the user : ", e);
        }
    }


    public UserRepresentation updateUserMap(UpdateRequest user){
        UserRepresentation userRep = new UserRepresentation();
        userRep.setFirstName(user.getFirstName());
        userRep.setLastName(user.getLastName());
        return userRep;
    }


    @Override
    public void emailVerification(String userId) {
        Keycloak keycloak = getKeycloakInstance();
        keycloak.realm(realm).users().get(userId).executeActionsEmail(singletonList("VERIFY_EMAIL"));
    }

    @Override
    public UserRepresentation mapUserRep(UserRequest user) {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setFirstName(user.getFirstName());
        userRep.setLastName(user.getLastName());
        userRep.setEmail(user.getEmail());
        userRep.setEnabled(true);
        userRep.setEmailVerified(false);
        userRep.setRequiredActions(singletonList("VERIFY_EMAIL"));
        userRep.setRequiredActions(singletonList("UPDATE_PASSWORD"));
        List<CredentialRepresentation> creds = new ArrayList<>();
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue("12345");
        cred.setTemporary(true);
        creds.add(cred);
        userRep.setCredentials(creds);
        return userRep;
    }


    @Override
    public ResponseEntity<?> forgotPassword(String username){
        UsersResource usersResource = getKeycloakInstance().realm(realm).users();

        List<UserRepresentation> userRepresentations = usersResource.search(username);
        Optional<UserRepresentation> userOptional = userRepresentations.stream().findFirst();

        if (userOptional.isPresent()) {
            UserRepresentation userRepresentation = userOptional.get();
            UserResource userResource = usersResource.get(userRepresentation.getId());
            List<String> actions = new ArrayList<>();
            actions.add("UPDATE_PASSWORD");
            userResource.executeActionsEmail(actions);
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.notFound().build();
    }

    /**
     * Método para desabilitar una cuenta de usuario en Keycloak.
     * @param userId id del usuario a desabilitar.
     * @return true si la cuenta fue desabilitada, false en caso contrario.
     */

    @Override
    public boolean deleteAccount(String userId) {
        Keycloak keycloak = getKeycloakInstance();
        try {
            UserRepresentation user = keycloak.realm(realm).users().get(userId).toRepresentation();
            user.setEnabled(false);
            keycloak.realm(realm).users().get(userId).update(user);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}