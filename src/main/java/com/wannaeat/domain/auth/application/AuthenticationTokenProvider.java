package com.wannaeat.domain.auth.application;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationTokenProvider {
    public UsernamePasswordAuthenticationToken createToken(String loginId, String password) {
        return new UsernamePasswordAuthenticationToken(loginId, password);
    }
}
