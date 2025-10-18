package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;

    // FIXED API7: Proper security configuration with CORS, security headers, and proper authorization
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // FIXED: Proper CORS configuration with restricted origins
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless; but add CSRF for state-changing in real apps
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // http.authorizeHttpRequests(reg -> reg
        //         .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
        //         // VULNERABILITY: broad permitAll on GET allows data scraping (API1/2 depending on context)
        //         .requestMatchers(HttpMethod.GET, "/api/**").permitAll()
        //         .requestMatchers("/api/admin/**").hasRole("ADMIN")
        //         .anyRequest().authenticated()
        // );


        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                
                .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/users").hasRole("ADMIN")     // List users - admin only
                .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasRole("ADMIN") // Delete users - admin only

                .requestMatchers("/api/**").authenticated()

                .anyRequest().authenticated()
        );

        // http.headers(h -> h.frameOptions(f -> f.disable())); // allow H2 console

        http.headers(headers -> headers
            .frameOptions(frameOptions -> frameOptions.sameOrigin())  // Allow same origin for H2
            .contentTypeOptions(contentType -> {})
            .httpStrictTransportSecurity(hsts -> hsts
                .maxAgeInSeconds(31536000)
                .includeSubDomains(true))
        );

        http.addFilterBefore(new JwtFilter(secret), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("http://localhost:*"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);  // Cache CORS preflight for 1 hour
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        JwtFilter(String secret) { this.secret = secret; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    Claims c = Jwts.parserBuilder()
                        .setSigningKey(secret.getBytes())
                        .requireIssuer("owasp-api-vuln-lab")        // Validate issuer
                        .requireAudience("api-users")               // Validate audience
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
                    
                    // Additional validation
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    
                    // Validate required claims exist
                    if (user == null || user.trim().isEmpty()) {
                        throw new JwtException("Missing or invalid subject");
                    }
                    
                    if (role == null || role.trim().isEmpty()) {
                        throw new JwtException("Missing or invalid role");
                    }
                    
                    // Set authentication
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(
                        user, null,
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                    );
                    SecurityContextHolder.getContext().setAuthentication(authn);
                    
                } catch (ExpiredJwtException e) {
                    // FIXED: Handle expired tokens specifically
                    handleJwtError(response, "Token expired", HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } catch (UnsupportedJwtException e) {
                    // FIXED: Handle unsupported tokens
                    handleJwtError(response, "Unsupported token format", HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } catch (MalformedJwtException e) {
                    // FIXED: Handle malformed tokens
                    handleJwtError(response, "Malformed token", HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } catch (SecurityException e) {
                    // FIXED: Handle signature validation failures (using SecurityException instead of deprecated SignatureException)
                    handleJwtError(response, "Invalid token signature", HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                } catch (JwtException e) {
                    // FIXED: Handle all other JWT exceptions with proper logging
                    System.err.println("JWT validation failed: " + e.getMessage());
                    handleJwtError(response, "Invalid token", HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
            }
            chain.doFilter(request, response);
        }
        
        // Helper method to handle JWT errors consistently
        private void handleJwtError(HttpServletResponse response, String message, int status) 
                throws IOException {
            SecurityContextHolder.clearContext();
            response.setStatus(status);
            response.setContentType("application/json");
            response.getWriter().write(String.format("{\"error\":\"%s\"}", message));
            response.getWriter().flush();
        }
    }
}
