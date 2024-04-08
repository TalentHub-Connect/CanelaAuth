package com.talenthub.auth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.response.TokenResponse;
import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import com.talenthub.auth.security.KeycloakSecurityUtil;
import com.talenthub.auth.service.intf.IKeycloakService;
import com.talenthub.auth.tool.ObjectToUrlEncodedConverter;
import org.keycloak.admin.client.Keycloak;

import org.keycloak.representations.idm.RoleRepresentation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;


import java.util.List;
import java.util.Map;


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
        Keycloak keycloak = keycloakUtil.getKeycloakInstance();
        String userId = keycloak.realm(realm).users().search(username).get(0).getId();
        List<RoleRepresentation> roles = keycloak.realm(realm).users().get(userId).roles().realmLevel().listAll();
        for (RoleRepresentation role : roles) {
            return role.getName();
        }
        return null;
    }
}