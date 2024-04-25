package com.talenthub.auth.controller;

import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.request.UpdateRequest;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/talentsoft/auth")
@SecurityRequirement(name = "Keycloak")
public class TalentSoftController {
    private final IKeycloakService keycloakService;

    private final CryptoUtil cryptoUtil;

    @Autowired
    public TalentSoftController(IKeycloakService keycloakService, CryptoUtil cryptoUtil) {
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
     * Este metodo permite actualizar los datos de un usuario
     * @param username Nombre de usuario
     * @param updateRequest Datos a actualizar
     * @return Mensaje de confirmación ó mensaje de error
     */
    @Operation(summary = "Actualizar datos de un usuario", description = "Actualiza los datos de un usuario")
    @ApiResponse(responseCode = "200", description = "Usuario actualizado")
    @ApiResponse(responseCode = "404", description = "Error al actualizar el usuario")
    @Parameter(name = "username", description = "Nombre de usuario", required = true)
    @Parameter(name = "enterprise", description = "Empresa del usuario", required = true)
    @PutMapping("/users/{username}")
    public ResponseEntity<?> updateUser(@PathVariable("username") String username, @RequestBody UpdateRequest updateRequest, @RequestParam String enterprise) {
        try {
            if (keycloakService.updateUser(username, updateRequest, enterprise))
                return ResponseEntity.status(HttpStatus.OK).body(new MessageResponse("Usuario actualizado"));
            else return ResponseEntity.notFound().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Este metodo permite crear un usuario con un rol desde frontend
     * @param userRequest Datos del usuario
     * @param role Rol del usuario
     * @return Mensaje de confirmación ó mensaje de error
     */

    @Operation(summary = "Crear un usuario con un rol", description = "Crea un usuario con un rol específico.")
    @ApiResponse(responseCode = "201", description = "Usuario creado")
    @ApiResponse(responseCode = "400", description = "Error al crear el usuario")
    @PreAuthorize("hasAnyAuthority('ADMIN', 'ADMIN_CANELA')")
    @PostMapping("{enterprise}/{role}")
    public ResponseEntity<?> CreateUser(@RequestBody UserRequest userRequest, @PathVariable String role, @PathVariable("enterprise") String enterprise) {
        if (role == null || role.isEmpty()) {
            return ResponseEntity.badRequest().body("Role is required");
        }
        List<String> currentAuthorityRoles = SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        List<String> allowedRolesForAdminCanela = Arrays.asList("ADMIN", "MARKETING", "SOPORTE", "CUENTAS");
        List<String> allowedRolesForAdmin = Arrays.asList("RECLUTAMIENTO", "DESPIDO", "SST", "NOMINA_ELECTRONICA", "BI");

        if (currentAuthorityRoles.contains("ADMIN_CANELA") && !allowedRolesForAdminCanela.contains(role.toUpperCase())) {
            return ResponseEntity.badRequest().body("ADMIN_CANELA can only create users with the following roles: " + String.join(", ", allowedRolesForAdminCanela));
        }

        if (currentAuthorityRoles.contains("ADMIN") && !allowedRolesForAdmin.contains(role.toUpperCase())) {
            return ResponseEntity.badRequest().body("ADMIN can only create users with the following roles: " + String.join(", ", allowedRolesForAdmin));
        }

        ResponseEntity<?> response = keycloakService.createUserWithRole(userRequest, role, enterprise);
        if (response.getStatusCode().is2xxSuccessful()) {
            return ResponseEntity.status(HttpStatus.CREATED).body("User with role " + role + " created");
        } else {
            return ResponseEntity.badRequest().body("Error creating a user with role " + role);
        }
    }


    /**
     * Este metodo permite restaurar la contraseña de un usuario
     * @param username Nombre de usuario
     * @return Mensaje de confirmación ó mensaje de error
     */

    @Operation(summary = "Restaurar contraseña", description = "Envia un correo para restaurar la contraseña")
    @ApiResponse(responseCode = "200", description = "Correo enviado")
    @ApiResponse(responseCode = "404", description = "Error al enviar el correo")
    @Parameter(name = "username", description = "Nombre de usuario", required = true)
    @PostMapping("/{username}/forgot-password")
    public ResponseEntity<?> forgotPassword(@PathVariable("username") String username) {
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
