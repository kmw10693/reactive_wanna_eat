package com.wannaeat.global.jwt;

import com.wannaeat.domain.auth.domain.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationConverter {

    private final JwtValidator jwtValidator;
    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public Mono<Authentication> getAuthentication(String token) {
        return redisTemplate.opsForValue().get("blacklist:" + token)
                .flatMap(blacklisted -> Mono.error(new RuntimeException("로그아웃된 토큰입니다.")))
                .switchIfEmpty(Mono.defer(() -> {
                    Long memberId = jwtValidator.getAllClaimsFromToken(token)
                            .get("userPK", Long.class);
                    CustomUserDetails customUserDetails = CustomUserDetails.toCustomUser(memberId);
                    return Mono.just(new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities()));
                }))
                .cast(Authentication.class);
    }

    public Long getMemberId(Authentication authentication) {
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        return customUserDetails.getMemberId();
    }
}
