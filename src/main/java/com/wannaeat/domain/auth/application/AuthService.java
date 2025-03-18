package com.wannaeat.domain.auth.application;

import com.wannaeat.domain.auth.dto.request.AuthRequest;
import com.wannaeat.domain.auth.dto.response.AuthResponse;
import com.wannaeat.global.jwt.JwtAuthenticationConverter;
import com.wannaeat.global.jwt.JwtProvider;
import com.wannaeat.global.jwt.JwtValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtProvider jwtProvider;
    private final ReactiveAuthenticationManager authenticationManager;
    private final AuthenticationTokenProvider authenticationTokenProvider;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;
    private final JwtValidator jwtValidator;
    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public Mono<AuthResponse> login(Mono<AuthRequest> authRequest) {
        return authRequest
                .flatMap(login -> authenticationManager
                        .authenticate(authenticationTokenProvider.createToken(
                                login.loginId(), login.password()))
                        .map(jwtAuthenticationConverter::getMemberId)
                        .map(jwtProvider::generateAccessToken))
                .map(AuthResponse::of);
    }


    public Mono<String> logout(String token) {
        return Mono.fromCallable(() -> {
                    jwtValidator.validateToken(token); // 토큰 유효성 검사
                    return jwtValidator.getAllClaimsFromToken(token)
                            .getExpiration()
                            .getTime();
                })
                .flatMap(expirationTime -> {
                    long now = System.currentTimeMillis();
                    long ttl = (expirationTime - now) / 1000; // TTL 계산 (초 단위)

                    return redisTemplate.opsForValue()
                            .set("blacklist:" + token, "logout", Duration.ofSeconds(ttl)) // 블랙리스트 등록
                            .thenReturn("로그아웃 성공");
                });
    }
}