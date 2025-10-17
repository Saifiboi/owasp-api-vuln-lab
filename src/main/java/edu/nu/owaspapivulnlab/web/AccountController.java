package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // VULNERABILITY(API1: BOLA) - no check whether account belongs to caller
    // @GetMapping("/{id}/balance")
    // public Double balance(@PathVariable("id") Long id) {
    //     Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
    //     return a.getBalance();
    // }


    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable("id") Long id, Authentication auth) {
        // Extract authenticated user from JWT token
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body(Collections.singletonMap("error", "Authentication required"));
        }
        
        // Find the authenticated user
        AppUser currentUser = users.findByUsername(auth.getName())
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Find the requested account
        Account account = accounts.findById(id)
            .orElseThrow(() -> new RuntimeException("Account not found"));
        
        // AUTHORIZATION CHECK - Verify account belongs to authenticated user
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).body(Collections.singletonMap("error", "Access denied - Account does not belong to you"));
        }
        
        // Return balance only if user owns the account
        return ResponseEntity.ok(Collections.singletonMap("balance", account.getBalance()));
    }

    // VULNERABILITY(API4: Unrestricted Resource Consumption) - no rate limiting on transfer
    // VULNERABILITY(API5/1): no authorization check on owner

    private final Map<String, Integer> transferCounts = new ConcurrentHashMap<>();
    private static final int MAX_TRANSFERS = 5;
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable("id") Long id, @RequestParam("amount") Double amount, Authentication auth) {
        // Check auth
        if (auth == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }
        
        // Get user and account
        AppUser user = users.findByUsername(auth.getName()).orElseThrow();
        Account account = accounts.findById(id).orElseThrow();
        
        // API5: Check ownership
        if (!account.getOwnerUserId().equals(user.getId())) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }
        
        // API4: Rate limiting
        String username = user.getUsername();
        if (transferCounts.getOrDefault(username, 0) >= MAX_TRANSFERS) {
            return ResponseEntity.status(429).body(Map.of("error", "Transfer limit exceeded"));
        }
        
        // Validate and transfer
        if (amount <= 0 || account.getBalance() < amount) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
        }
        
        account.setBalance(account.getBalance() - amount);
        accounts.save(account);
        transferCounts.put(username, transferCounts.getOrDefault(username, 0) + 1);
        
        return ResponseEntity.ok(Map.of("status", "ok", "remaining", account.getBalance()));
    }

    // Safe-ish helper to view my accounts (still leaks more than needed)
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
