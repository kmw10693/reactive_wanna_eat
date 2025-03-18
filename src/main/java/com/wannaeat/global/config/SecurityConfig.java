package com.wannaeat.global.config;

import com.wannaeat.domain.member.domain.MemberRepository;
import com.wannaeat.domain.auth.domain.CustomUserDetails;
import com.wannaeat.global.filter.JwtAuthenticationFilter;
import com.wannaeat.global.jwt.JwtAuthenticationConverter;
import com.wannaeat.global.jwt.JwtValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http,
                                            JwtValidator jwtValidator,
                                            JwtAuthenticationConverter jwtAuthenticationConverter,
                                            ReactiveAuthenticationManager reactiveAuthenticationManager) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authenticationManager(reactiveAuthenticationManager)
                .authorizeExchange(it -> it
                        .pathMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/members").permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(new JwtAuthenticationFilter(jwtValidator, jwtAuthenticationConverter), SecurityWebFiltersOrder.HTTP_BASIC)
                .build();
    }

    @Bean
    public ReactiveUserDetailsService userDetailsService(MemberRepository memberRepository) {
        return loginId -> memberRepository.findByLoginId(loginId)
                .map(CustomUserDetails::toCustomUser);
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(ReactiveUserDetailsService userDetailsService,
                                                                       PasswordEncoder passwordEncoder) {
        var authenticationManager = createProvider(userDetailsService);
        authenticationManager.setPasswordEncoder(passwordEncoder);
        return authenticationManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    private UserDetailsRepositoryReactiveAuthenticationManager createProvider(ReactiveUserDetailsService userDetailsService) {
        return new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
    }
}