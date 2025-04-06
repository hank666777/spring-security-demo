package com.demo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@Log4j2
public class JwtFilter extends OncePerRequestFilter {
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JwtFilter, do filter");
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        String jwtToken = null;
        if (authorization != null && authorization.startsWith("Bearer ")) {
            jwtToken = authorization.substring(7);
            // todo
//            String username = jwtTokenUtil.getUsernameFromToken(jwtToken);
//            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//
//            }
        }

        doFilter(request, response, filterChain);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String requestPath = request.getServletPath();
        boolean b = Arrays.stream(GlobalSecurityConfig.PROTECTED_PATH)
                .anyMatch(path -> pathMatcher.match(path, requestPath));
        log.info("JwtFilter, request uri: {}, should not filter: {}", requestPath, !b);
        return !b;
    }
}
