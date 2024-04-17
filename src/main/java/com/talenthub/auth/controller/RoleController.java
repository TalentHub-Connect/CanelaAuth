package com.talenthub.auth.controller;

import com.talenthub.auth.dto.response.MessageResponse;
import com.talenthub.auth.service.intf.IKeycloakRoleService;
import com.talenthub.auth.service.intf.IKeycloakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/talentsoft/roles")
public class RoleController {
    private final IKeycloakRoleService keycloakRoleService;

    @Autowired
    public RoleController(IKeycloakService keycloakService, IKeycloakRoleService keycloakRoleService) {
        this.keycloakRoleService = keycloakRoleService;
    }

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
}
