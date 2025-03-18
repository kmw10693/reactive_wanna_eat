package com.wannaeat.global.jwt;

import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
@Getter
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.accesstokenValid}")
    private String accessTokenValidity;

    @Value("${jwt.refreshtokenValid}")
    private String refreshTokenValidity;

    private SecretKey key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
}
