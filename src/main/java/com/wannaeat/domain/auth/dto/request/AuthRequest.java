package com.wannaeat.domain.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record AuthRequest(
        @NotBlank String loginId, @NotBlank String password
) {
}
