package com.demo.client.controller;

import com.demo.client.dto.LoginRequest;
import com.demo.vo.ResponseDto;
import jakarta.validation.Valid;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Log4j2
@RestController("/api/auth")
public class AuthorizationController {

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {

        return ResponseEntity.ok(
                ResponseDto.builder()
                        .status(ResponseDto.Status.STATUS_000)
                        .message(ResponseDto.Status.STATUS_000.getMessage())
                        .build()
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody LoginRequest request) {

        return ResponseEntity.ok(
                ResponseDto.builder()
                        .status(ResponseDto.Status.STATUS_000)
                        .message(ResponseDto.Status.STATUS_000.getMessage())
                        .build()
        );
    }
}
