package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

@Configuration
public class DataSeeder {
    @Bean
    CommandLineRunner seed(AppUserRepository users,PasswordEncoder passwordEncoder, AccountRepository accounts) {
        return args -> {
            if (users.count() == 0) {
                AppUser u1 = new AppUser();
                u1.setUsername("alice");
                u1.setPassword(passwordEncoder.encode("alice123"));
                u1.setEmail("alice@cydea.tech");
                // Don't set role/isAdmin - they default to USER/false
                u1 = users.save(u1);
                
                // Create admin user - manually set after creation
                AppUser u2 = new AppUser();
                u2.setUsername("bob");
                u2.setPassword(passwordEncoder.encode("bob123"));
                u2.setEmail("bob@cydea.tech");
                u2 = users.save(u2);
                
                // Manually set admin privileges (bypass JSON restrictions)
                u2.setRole("ADMIN");
                u2.setAdmin(true);
                users.save(u2);
                accounts.save(Account.builder().ownerUserId(u1.getId()).iban("PK00-ALICE").balance(1000.0).build());
                accounts.save(Account.builder().ownerUserId(u2.getId()).iban("PK00-BOB").balance(5000.0).build());
            }
        };
    }
}
