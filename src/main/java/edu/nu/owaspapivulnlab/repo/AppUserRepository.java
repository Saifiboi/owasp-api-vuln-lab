package edu.nu.owaspapivulnlab.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import edu.nu.owaspapivulnlab.model.AppUser;

import java.util.List;
import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);

    List<AppUser> findByUsernameContainingIgnoreCase(String username);
}
