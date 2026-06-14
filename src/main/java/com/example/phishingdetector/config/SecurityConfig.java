package com.example.phishingdetector.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/static/**", "/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/index.html", true)
                )
                .logout(logout -> logout
                        .addLogoutHandler(new CookieClearingLogoutHandler("JSESSIONID")) // clears session cookie
                        .logoutSuccessHandler((HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
                            String issuer = "https://dev-eyz4r1204za77l53.us.auth0.com";
                            String clientId = "cBmn6qryUPKDh9x6tmCozG4y3uzprj4u";
                            String returnTo = "http://localhost:8080/";

                            if (request.getSession(false) != null) {
                                request.getSession().invalidate();
                            }

                            String logoutUrl = issuer + "/v2/logout?client_id=" + clientId + "&returnTo=" + returnTo;
                            response.sendRedirect(logoutUrl);
                        })
                );

        return http.build();
    }
}
