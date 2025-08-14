package com.demo.jwtminiproject.web.dto;

import jakarta.validation.constraints.NotBlank;

public class RefreshRequest {
    @NotBlank public String refreshToken;
}