package com.demo.jwtminiproject.web;


import com.demo.jwtminiproject.security.JwtService;
import com.demo.jwtminiproject.security.TokenBlacklist;
import com.demo.jwtminiproject.web.dto.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final TokenBlacklist blacklist;

    public AuthController(AuthenticationManager authManager, JwtService jwtService, TokenBlacklist blacklist) {
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.blacklist = blacklist;
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest req) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username, req.password)
        );
        UserDetails user = (UserDetails) auth.getPrincipal();
        List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .map(r -> r.replaceFirst("^ROLE_", ""))
                .collect(Collectors.toList());
        String access = jwtService.generateAccessToken(user.getUsername(), roles);
        String refresh = jwtService.generateRefreshToken(user.getUsername());
        return new TokenResponse(access, refresh);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest req) {
        Jws<Claims> jws = jwtService.parse(req.refreshToken);
        Claims claims = jws.getBody();
        if (!"refresh".equals(claims.get("token_type"))) {
            throw new IllegalArgumentException("Not a refresh token");
        }
        String username = claims.getSubject();
        String access = jwtService.generateAccessToken(username, List.of("USER"));
        String newRefresh = jwtService.generateRefreshToken(username);
        return new TokenResponse(access, newRefresh);
    }

    @PostMapping("/logout")
    public void logout(@Valid @RequestBody LogoutRequest req) {
        Jws<Claims> jws = jwtService.parse(req.token);
        Claims claims = jws.getBody();
        String jti = claims.getId();
        long exp = claims.getExpiration().toInstant().getEpochSecond();
        blacklist.revoke(jti, exp);
    }
}

