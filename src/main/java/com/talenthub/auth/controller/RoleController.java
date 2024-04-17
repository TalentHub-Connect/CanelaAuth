package com.talenthub.auth.controller;

import com.talenthub.auth.dto.response.MessageResponse;
import com.talenthub.auth.exception.ErrorKeycloakServiceException;
import com.talenthub.auth.service.intf.IKeycloakRoleService;
import com.talenthub.auth.service.intf.IKeycloakService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/talentsoft/roles")
@SecurityRequirement(name = "Keycloak")
public class RoleController {
    private final IKeycloakRoleService keycloakRoleService;

    @Autowired
    public RoleController(IKeycloakService keycloakService, IKeycloakRoleService keycloakRoleService) {
        this.keycloakRoleService = keycloakRoleService;
    }

    /**
     * Crea un nuevo rol en Keycloak.
     * @param roleName Nombre del rol a crear.
     * @return Respuesta indicando el resultado de la operación.
     */

    @PreAuthorize("hasAnyAuthority('ADMIN', 'ADMIN_CANELA')")
    @PostMapping("/create")
    public ResponseEntity<?> createRole(@RequestParam String roleName) {
        try {
            keycloakRoleService.createRole(roleName);
            return ResponseEntity.ok(new MessageResponse("Role successfully created"));
        } catch ( ErrorKeycloakServiceException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse("Error creating role: " + e.getMessage()));
        }
    }

    /**
     * Asigna un rol a un usuario en Keycloak.
     * @param username Nombre de usuario al que se le asignará el rol.
     * @param roles Lista de roles a asignar.
     * @return Respuesta indicando el resultado de la operación.
     */

    @PutMapping("/change-role/{username}")
    @PreAuthorize("hasAnyAuthority('ADMIN' , 'ADMIN_CANELA')")
    public ResponseEntity<?> changeRole(@PathVariable String username, @RequestBody List<String> roles) {
        try {
            keycloakRoleService.changeUserRoles(username,roles);
            return ResponseEntity.ok(new MessageResponse("Role changed"));
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Elimina un rol en Keycloak.
     * @param roleName Nombre del rol a eliminar.
     * @return Respuesta indicando el resultado de la operación.
     */
    @PreAuthorize("hasAnyAuthority('ADMIN', 'ADMIN_CANELA')")
    @DeleteMapping("/delete/{roleName}")
    public ResponseEntity<?> deleteRole(@PathVariable String roleName) {
        try {
            keycloakRoleService.deleteRole(roleName);
            return ResponseEntity.ok(new MessageResponse("Role successfully deleted"));
        } catch (ErrorKeycloakServiceException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new MessageResponse("Error deleting role: " + e.getMessage()));
        }
    }
}
