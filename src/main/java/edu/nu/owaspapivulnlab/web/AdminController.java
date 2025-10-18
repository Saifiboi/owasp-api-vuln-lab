package edu.nu.owaspapivulnlab.web;

import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    private final AppUserRepository users;

    public AdminController(AppUserRepository users) {
        this.users = users;
    }

    // VULNERABILITY(API7: Security Misconfiguration) - may be exposed via incorrect matcher order
    @GetMapping("/metrics")
    public ResponseEntity<?> metrics(Authentication auth) {  
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        AppUser currentUser = users.findByUsername(auth.getName())
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        if (!currentUser.isAdmin()) {
            return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
        }
        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        Map<String, Object> metricsMap = new HashMap<>();
        metricsMap.put("uptimeMs", rt.getUptime());
        metricsMap.put("javaVersion", System.getProperty("java.version"));
        metricsMap.put("threads", ManagementFactory.getThreadMXBean().getThreadCount());
        return ResponseEntity.ok(metricsMap);
    }
}
