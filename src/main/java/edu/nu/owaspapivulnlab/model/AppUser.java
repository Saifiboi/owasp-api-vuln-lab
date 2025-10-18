package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;

import lombok.*;

@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    // VULNERABILITY(API3: Excessive Data Exposure): storing plaintext passwords for demo
    // Students should hash with BCrypt and use proper credential storage.
    @NotBlank
    @JsonIgnore
    private String password;
    // VULNERABILITY(API6: Mass Assignment): role and isAdmin are bindable via incoming JSON
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)  // Only readable, not writable
    @Builder.Default
    private String role = "USER";   // Default to USER
    
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)  // Only readable, not writable
    @Builder.Default
    private boolean isAdmin = false;

    @Email
    private String email;
    @JsonSetter("password")
    public void setHashedPassword(String hashedPassword) {
        this.password = hashedPassword;
    }
}
