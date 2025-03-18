package com.wannaeat.domain.auth.presentation;

import com.wannaeat.domain.auth.application.AuthService;
import com.wannaeat.domain.auth.dto.request.AuthRequest;
import com.wannaeat.domain.auth.dto.response.AuthResponse;
import com.wannaeat.global.filter.JwtAuthenticationFilter;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@Validated
public class AuthController {

    private final AuthService authService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @PostMapping("/login")
    public Mono<AuthResponse> login(@Valid @RequestBody Mono<AuthRequest> authRequest) {
        return authService.login(authRequest);
    }

    @PatchMapping("/logout")
    public Mono<String> logout(ServerHttpRequest request) {
        String token = jwtAuthenticationFilter.resolveToken(request);
        return authService.logout(token);
    }
}
