package com.talenthub.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.talenthub.auth.dto.request.AuthenticationRequest;
import com.talenthub.auth.dto.request.UserRequest;
import com.talenthub.auth.dto.response.MessageResponse;
import com.talenthub.auth.dto.response.TokenResponse;
import com.talenthub.auth.service.intf.IKeycloakService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IKeycloakService keycloakService;

    private String mapToJson(Object obj) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(obj);
    }

    @Test
	void getAccessTokenSuccess() throws Exception {
    AuthenticationRequest request = createAuthenticationRequestSuccess();
    TokenResponse tokenResponse = TokenResponse.builder()
                                                .access_token("access_token")
                                                .role("ADMIN")
                                                .build();

    when(keycloakService.getAccessToken(any(AuthenticationRequest.class))).thenReturn(tokenResponse);

    MvcResult result = mockMvc.perform(post("/api/talentsoft/auth/login")
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapToJson(request)))
                .andReturn();

    assertEquals(200, result.getResponse().getStatus());
    String content = result.getResponse().getContentAsString();
    assertEquals("{\"access_token\":\"access_token\",\"role\":\"ADMIN\"}", content);
}


    private AuthenticationRequest createAuthenticationRequestSuccess() {
        return new AuthenticationRequest("sebasorjuela", "12345");
    }

@Test
@WithMockUser(authorities = "ADMIN")
void whenCreateUserWithValidData_thenReturnsCreated() throws Exception {
    UserRequest userRequest = new UserRequest("hola", "email@example.com", "12345");
    String role = "ADMIN";

    ResponseEntity<MessageResponse> createdResponse = ResponseEntity
        .status(HttpStatus.CREATED)
        .body(new MessageResponse("User with role ADMIN created"));
	doReturn(createdResponse).when(keycloakService).createUserWithRole(any(UserRequest.class), eq(role), any());

    mockMvc.perform(post("/api/talentsoft/auth/" + role)
            .contentType(MediaType.APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(userRequest)))
        .andExpect(status().isCreated())
        .andExpect(content().string("User with role ADMIN created"));
}


@Test
@WithMockUser(authorities = "ADMIN")
void whenForgotPasswordForExistingUser_thenReturnsOk() throws Exception {
    String username = "ticaso";
    ResponseEntity<MessageResponse> responseEntity = new ResponseEntity<>(new MessageResponse("Correo enviado"), HttpStatus.OK);

    doReturn(responseEntity).when(keycloakService).forgotPassword(username);

    mockMvc.perform(post("/api/talentsoft/auth/" + username + "/forgot-password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Correo enviado"));
}



@Test
@WithMockUser(authorities = "ADMIN")
void whenDeleteUser_thenReturnsOk() throws Exception {
    String id = "b54b672c-8c02-4b56-b59a-7b695d0a8f94";
    when(keycloakService.deleteAccount(id)).thenReturn(true);

    mockMvc.perform(delete("/api/talentsoft/auth/users/" + id))
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("$.message").value("Usuario desabilitado"));
}

}
