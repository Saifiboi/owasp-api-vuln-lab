package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    // VULNERABILITY(API8): HS256 with trivial key, long TTL, missing issuer/audience
    public String issue(String subject, Map<String, Object> claims) {
        validateSecret();
        return Jwts.builder()
        .setSubject(subject)
        .setIssuer("owasp-api-vuln-lab")        
        .setAudience("api-users")               
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + ttlSeconds * 1000))
        .addClaims(claims)
        .signWith(SignatureAlgorithm.HS256, secret.getBytes())
        .compact();
    }
    private void validateSecret() {
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException("JWT secret must be at least 256 bits (32 characters)");
        }
    }
}
