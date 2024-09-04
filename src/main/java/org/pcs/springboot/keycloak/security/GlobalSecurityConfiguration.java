package org.pcs.springboot.keycloak.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class GlobalSecurityConfiguration {

    private final ClientRegistrationRepository clientRegistrationRepository;

    public GlobalSecurityConfiguration(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers( "/mgmt/**", "/swagger-ui/**", "/v3/api-docs/**", "/public/**").permitAll() // Permitir acesso público a essas rotas
                        .anyRequest().authenticated() // Todas as outras requisições requerem autenticação
                )
                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository) // Configura o ClientRegistrationRepository
                        .loginPage("/oauth2/authorization/keycloak") // Define a URL para redirecionar ao login do Keycloak
                        .defaultSuccessUrl("/", true) // Redireciona para a página principal após o login
                        .failureUrl("/login?error") // Redireciona para uma página de erro em caso de falha na autenticação
                );
        return http.build();
    }

}