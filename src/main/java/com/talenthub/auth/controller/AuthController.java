package com.talenthub.auth.controller;

import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.request.UserRequest;
import com.talenthub.auth.dto.response.MessageResponse;
import com.talenthub.auth.dto.response.TokenResponse;
import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import com.talenthub.auth.service.intf.IKeycloakService;
import com.talenthub.auth.tool.CryptoUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/talentsoft/auth")
@SecurityRequirement(name = "Keycloak")
public class AuthController {
    private final IKeycloakService keycloakService;

    private final CryptoUtil cryptoUtil;

    @Autowired
    public AuthController(IKeycloakService keycloakService, CryptoUtil cryptoUtil) {
        this.keycloakService = keycloakService;
        this.cryptoUtil  = cryptoUtil;
    }

    /**
     * Obtiene el token de acceso al sistema
     * @param request Datos de autenticación (username y password)
     * @return Token de acceso
     */

    @Operation(summary = "Obtener el token de acceso al sistema", description = "Obtiene el token")
    @ApiResponse(responseCode = "200", description = "Token obtenido")
    @ApiResponse(responseCode = "400", description = "Error al obtener el token de acceso")
    @PostMapping("/login")
    public ResponseEntity<?> getAccessToken(@RequestBody AuthenticationRequest request) throws ErrorKeycloakServiceException {
        String password = cryptoUtil.decrypt(request.getPassword());
        System.out.println(password);
        request.setPassword(password);
        TokenResponse token = keycloakService.getAccessToken(request);
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    /**
     * This method allows you to create a user with a specific role
     * @param userRequest User data
     * @param role The role to assign to the user
     * @return Message of confirmation or error message
     */

    @Operation(description = "Create a user with a specific role")
    @ApiResponse(responseCode = "201", description = "User created")
    @ApiResponse(responseCode = "400", description = "Error creating the user")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'ADMIN_CANELA')")
    @PostMapping("/{role}")
    public ResponseEntity<?> CreateUser(@RequestBody UserRequest userRequest, @PathVariable String role) {
        if (role == null || role.isEmpty()) {
            return ResponseEntity.badRequest().body("Role is required");
        }

        // Obtener los roles de la autoridad actual
        List<String> currentAuthorityRoles = SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .map(grantedAuthority -> ((SimpleGrantedAuthority) grantedAuthority).getAuthority())
                .toList();

        // Definir los roles permitidos para ADMIN_CANELA
        List<String> allowedRolesForAdminCanela = Arrays.asList("ADMIN", "MARKETING", "SOPORTE", "CUENTAS");
        // Definir los roles permitidos para ADMIN
        List<String> allowedRolesForAdmin = Arrays.asList("RECLUTAMIENTO", "DESPIDO", "SST", "NOMINA_ELECTRONICA", "BI");

        if (currentAuthorityRoles.contains("ADMIN_CANELA") && !allowedRolesForAdminCanela.contains(role.toUpperCase())) {
            return ResponseEntity.badRequest().body("ADMIN_CANELA can only create users with the following roles: " + String.join(", ", allowedRolesForAdminCanela));
        }

        if (currentAuthorityRoles.contains("ADMIN") && !allowedRolesForAdmin.contains(role.toUpperCase())) {
            return ResponseEntity.badRequest().body("ADMIN can only create users with the following roles: " + String.join(", ", allowedRolesForAdmin));
        }
        ResponseEntity<?> response = keycloakService.createUserWithRole(userRequest, role);
        if (response.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.CREATED).body("User with role " + role + " created");
        } else {
            return ResponseEntity.badRequest().body("Error creating a user with role " + role);
        }
    }

    /**
     * This method allows you reset the password of a user
     * @param username The username to reset the password
     * @return Message of confirmation or error message
     */

    @Operation(summary = "Restaurar contraseña", description = "Envia un correo para restaurar la contraseña")
    @ApiResponse(responseCode = "200", description = "Correo enviado")
    @ApiResponse(responseCode = "404", description = "Error al enviar el correo")
    @Parameter(name = "username", description = "Nombre de usuario", required = true)
    @PostMapping("/{username}/forgot-password")
    public ResponseEntity<?> forgotPassword(@PathVariable String username) {
        ResponseEntity<?> response = keycloakService.forgotPassword(username);
        if (response.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.ok(new MessageResponse("Correo enviado"));
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    @Operation(summary = "Desabilitar un usuario", description = "Desabilita un usuario")
    @ApiResponse(responseCode = "200", description = "Usuario desabilitado")
    @ApiResponse(responseCode = "404", description = "Error al desabilitar el usuario")
    @Parameter(name = "id", description = "Identificador del usuario", required = true)
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @DeleteMapping(value = "/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable("id") String id) {
        try {
            if (keycloakService.deleteAccount(id))
                return ResponseEntity.status(HttpStatus.OK).body(new MessageResponse("Usuario desabilitado"));
            else return ResponseEntity.notFound().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }


}
