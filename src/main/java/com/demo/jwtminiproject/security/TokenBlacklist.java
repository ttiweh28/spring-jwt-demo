package com.demo.jwtminiproject.security;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TokenBlacklist {

    private final Map<String, Long> revoked = new ConcurrentHashMap<>();

    public void revoke(String jti, long expEpochSeconds) {
        revoked.put(jti, expEpochSeconds);
    }

    public boolean isRevoked(String jti) {
        Long exp = revoked.get(jti);
        if (exp == null) return false;
        if (Instant.now().getEpochSecond() > exp) {
            revoked.remove(jti);
            return false;
        }
        return true;
    }
}
