package com.demo.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;

public interface ExternalService {

    ResponseEntity<?> login(HttpServletRequest request);
}
