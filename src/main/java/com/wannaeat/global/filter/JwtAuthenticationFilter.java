package com.wannaeat.global.filter;

import com.wannaeat.global.jwt.JwtAuthenticationConverter;
import com.wannaeat.global.jwt.JwtValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@Slf4j
@Component
public class JwtAuthenticationFilter implements WebFilter {

    public static final String HEADER_PREFIX = "Bearer ";
    private final JwtValidator jwtValidator;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = resolveToken(exchange.getRequest());
        log.debug("JWT Token {}", token);
        if (StringUtils.hasText(token) && this.jwtValidator.validateToken(token)) {
            return this.jwtAuthenticationConverter.getAuthentication(token)
                    .flatMap(authentication -> chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication)));
        }
        return chain.filter(exchange);

    }

    public String resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        log.debug("Authorization Header: {}", bearerToken);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)) {
            log.debug("Extracted Token: {}", bearerToken.substring(7));
            return bearerToken.substring(7);
        }
        return null;
    }
}