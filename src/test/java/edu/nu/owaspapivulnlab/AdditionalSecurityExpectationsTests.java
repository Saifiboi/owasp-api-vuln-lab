package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import java.util.Date;
@SpringBootTest
@AutoConfigureMockMvc
class AdditionalSecurityExpectationsTests {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper om;

    String login(String user, String pw) throws Exception {
        String res = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\""+user+"\",\"password\":\""+pw+"\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode n = om.readTree(res);
        return n.get("token").asText();
    }

    @Test
    void protected_endpoints_require_authentication() throws Exception {
        // Expectation in fixed app: /api/users requires auth -> 401
        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized()); // Fails now due to permitAll on GET
    }

    @Test
    void delete_user_requires_admin() throws Exception {
        String tUser = login("alice","alice123"); // not admin
        mvc.perform(delete("/api/users/1").header("Authorization","Bearer "+tUser))
                .andExpect(status().isForbidden()); // Fails now
    }

    @Test
    void create_user_does_not_allow_role_escalation() throws Exception {
        // In fixed app, server should ignore role/isAdmin from payload & return 201
        String payload = "{\"username\":\"eve2\",\"password\":\"pw\",\"email\":\"e2@e\",\"role\":\"ADMIN\",\"isAdmin\":true}";
        mvc.perform(post("/api/users").contentType(MediaType.APPLICATION_JSON).content(payload))
                .andExpect(status().isCreated()) // Fails now (200 OK)
                .andExpect(jsonPath("$.role", anyOf(nullValue(), is("USER")))) // Fails now (ADMIN)
                .andExpect(jsonPath("$.isAdmin", anyOf(nullValue(), is(false)))); // Fails now (true)
    }

    @Test
    void jwt_without_issuer_audience_rejected() throws Exception {
        // Create a token WITHOUT proper issuer/audience
        String invalidToken = createTokenWithoutIssuerAudience("alice");
        mvc.perform(get("/api/accounts/mine").header("Authorization","Bearer "+invalidToken))
                .andExpect(status().isUnauthorized()); // Should fail
    }

    private String createTokenWithoutIssuerAudience(String username) {
        return Jwts.builder()
            .setSubject(username)
            // NO .setIssuer() or .setAudience() - vulnerable!
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000))
            .claim("role", "USER")
            .signWith(SignatureAlgorithm.HS256, "N8Z1bFBknlVq3vYwr1l8D7sA5t1W8u0qQh5w3g7c2hc=".getBytes())
            .compact();
    }

    @Test
    void account_owner_only_access() throws Exception {
        String alice = login("alice","alice123");
        // In fixed code this should be forbidden
        mvc.perform(get("/api/accounts/2/balance").header("Authorization","Bearer "+alice))
                .andExpect(status().isForbidden()); // Fails now
    }
}
