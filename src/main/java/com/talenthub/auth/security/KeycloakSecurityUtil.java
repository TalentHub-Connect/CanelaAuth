package com.talenthub.auth.security;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * class to get keycloak instance
 *
 */
@Component
public class KeycloakSecurityUtil implements DisposableBean {

    private Keycloak keycloak;
    @Value("${authServerUrl}")
    private String authServerUrl;
    @Value("${realm}")
    private String realm;
    @Value("${client-id}")
    private String clientId;
    @Value("${name}")
    private String username;
    @Value("${password}")
    private String password;

    /**
     * get keycloak instance
     *
     * @return Keycloak
     */
    public synchronized Keycloak getKeycloakInstance() {
        if (keycloak == null) {
            try {
                keycloak = KeycloakBuilder.builder()
                        .serverUrl(authServerUrl)
                        .realm(realm)
                        .clientId(clientId)
                        .grantType(OAuth2Constants.PASSWORD)
                        .username(username)
                        .password(password)
                        .build();
            } catch (Exception e) {
                throw new RuntimeException("Error al crear la instancia de Keycloak", e);
            }
        }
        return keycloak;
    }

    @Override
    public void destroy() {
        if (keycloak != null) {
            keycloak.close();
        }
    }
}
