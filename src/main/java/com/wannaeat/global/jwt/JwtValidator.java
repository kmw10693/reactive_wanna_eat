package com.wannaeat.global.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtValidator {

    private final JwtUtil jwtUtil;

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(jwtUtil.getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token) {
        try {
            getAllClaimsFromToken(token);
            log.debug("유효한 JWT 토큰: {}", token);
            return true;
        } catch (Exception e) {
            log.debug("JWT 검증 실패: {}", e.getClass());
            throw new JwtException("유효하지 않은 JWT 토큰입니다.");
        }
    }
}
