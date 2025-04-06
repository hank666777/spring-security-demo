package com.demo.config;

import com.demo.vo.ResponseDto;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.net.URI;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ResponseDto> handleNotFoundException(NoHandlerFoundException ex) {
        return ResponseEntity.notFound()
                .location(URI.create(ex.getRequestURL()))
                .build();
    }
}
