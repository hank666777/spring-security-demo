package com.demo.client.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/api/client")
public class ClientController {

    @GetMapping("/csrf")
    public String getCsrfToken(CsrfToken csrfToken) {
        return csrfToken.getToken();
    }
}
