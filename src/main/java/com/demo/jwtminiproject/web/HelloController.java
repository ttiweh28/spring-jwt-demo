package com.demo.jwtminiproject.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HelloController {

    @GetMapping("/api/hello")
    public Map<String, Object> hello(Authentication auth) {
        String user = auth != null ? auth.getName() : "anonymous";
        return Map.of("message", "Hello, " + user + "!");
    }
}