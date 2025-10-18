package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    // // VULNERABILITY(API1: BOLA/IDOR) - no ownership check, any authenticated OR anonymous GET (due to SecurityConfig) can fetch any user
    // @GetMapping("/{id}")
    // public AppUser get(@PathVariable("id") Long id) {
    //     return users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    // }


    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable("id") Long id, org.springframework.security.core.Authentication auth) {
        // Check if user is authenticated
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        
        // Get the authenticated user from JWT token
        AppUser currentUser = users.findByUsername(auth.getName())
            .orElseThrow(() -> new RuntimeException("Authenticated user not found"));
        
        // AUTHORIZATION CHECK - Users can only access their own profile
        if (!currentUser.getId().equals(id)) {
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden - You can only access your own profile"));
        }
        
        // Return the user data only if they own it
        AppUser user = users.findById(id)
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        return ResponseEntity.ok(user);
    }

    // VULNERABILITY(API6: Mass Assignment) - binds role/isAdmin from client
    @PostMapping
    public AppUser create(@Valid @RequestBody AppUser body) {
        // FIXED: Hash password with BCrypt before saving
        body.setPassword(passwordEncoder.encode(body.getPassword()));
        return users.save(body);
    }

    // VULNERABILITY(API9: Improper Inventory + API8 Injection style): naive 'search' that can be abused for enumeration
    @GetMapping("/search")
    public List<AppUser> search(@RequestParam String q) {
        return users.search(q);
    }

    // VULNERABILITY(API3: Excessive Data Exposure) - returns all users including sensitive fields
    @GetMapping
    public List<AppUser> list(Authentication auth) {
        
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        if (me == null) {
            throw new RuntimeException("Unauthorized");
        }
        if (me.isAdmin()) {
            return users.findAll();
        }

        return List.of(me);
    }

    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable("id") Long id, Authentication auth) {
        // Check authentication
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        
        // Get current user
        AppUser currentUser = users.findByUsername(auth.getName())
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Only admins can delete
        if (!currentUser.isAdmin()) {
            return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
        }
        
        // Check if user exists
        if (!users.existsById(id)) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }
        
        // Delete user
        users.deleteById(id);

        return ResponseEntity.ok(Map.of("status", "deleted"));
    }
}
