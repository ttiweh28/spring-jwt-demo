package com.demo.jwtminiproject.web.dto;

import jakarta.validation.constraints.NotBlank;

public class LogoutRequest {
    @NotBlank
    public String token;
}