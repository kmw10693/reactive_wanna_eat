package com.wannaeat.global.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtUtil jwtUtil;

    public String generateAccessToken(Long userId) {
        return generateToken(userId, Long.parseLong(jwtUtil.getAccessTokenValidity()));
    }

    public String generateRefreshToken(Long userId) {
        return generateToken(userId, Long.parseLong(jwtUtil.getRefreshTokenValidity()));
    }

    private String generateToken(Long userId, long expirationTime) {
        Instant now = Instant.now();
        Date expirationDate = Date.from(now.plusSeconds(expirationTime));

        log.debug("JWT 토큰 생성 - 유저 ID: {}, 만료 시간: {}", userId, expirationDate);

        return Jwts.builder()
                .claim("userPK", userId)
                .expiration(expirationDate)
                .issuedAt(Date.from(now))
                .signWith(jwtUtil.getKey(), Jwts.SIG.HS256)
                .compact();
    }
}
