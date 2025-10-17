package edu.nu.owaspapivulnlab.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder passwordEncoder;

    // Account lockout tracking
    private final Map<String, LockoutInfo> lockoutAttempts = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder;
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }
    private static class LockoutInfo {
        int attempts;
        long lockoutTime;
        
        LockoutInfo() {
            this.attempts = 0;
            this.lockoutTime = 0;
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req, HttpServletRequest request) {
        String clientKey = req.username() + "_" + request.getRemoteAddr(); // Username + IP combination
        
        // Check if account is locked
        if (isAccountLocked(clientKey)) {
            return ResponseEntity.status(429).body(Map.of("error", "Account temporarily locked due to too many failed attempts. Try again later."));
        }

        // FIXED: Use BCrypt for password verification instead of plaintext
        AppUser user = users.findByUsername(req.username()).orElse(null);
        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            // Reset lockout on successful login
            lockoutAttempts.remove(clientKey);
            
            // FIXED: Role comes from DATABASE (server-side), not client-side
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());  // Server-verified role from database
            claims.put("isAdmin", user.isAdmin());  // Server-verified admin status
            claims.put("userId", user.getId());  // Add user ID for verification
            
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        
        // Record failed attempt and potentially lock account
        recordFailedAttempt(clientKey);
        
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    private boolean isAccountLocked(String clientKey) {
        LockoutInfo info = lockoutAttempts.get(clientKey);
        if (info == null) return false;
        
        // Check if lockout period has expired
        if (System.currentTimeMillis() - info.lockoutTime > LOCKOUT_DURATION) {
            lockoutAttempts.remove(clientKey);
            return false;
        }
        
        return info.attempts >= MAX_ATTEMPTS;
    }

    private void recordFailedAttempt(String clientKey) {
        lockoutAttempts.compute(clientKey, (key, info) -> {
            if (info == null) {
                info = new LockoutInfo();
            }
            info.attempts++;
            if (info.attempts >= MAX_ATTEMPTS) {
                info.lockoutTime = System.currentTimeMillis(); // Start lockout timer
            }
            return info;
        });
    }
    
}
