package com.demo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.stereotype.Component;

import java.util.Date;

@RequiredArgsConstructor
@Component
public class JwtUtil {

    private final OAuth2AuthorizationServerProperties properties;
    private final OAuth2ResourceServerProperties resourceProperties;
    private static OAuth2AuthorizationServerProperties oAuth2AuthorizationServerProperties;
    private static OAuth2ResourceServerProperties oauth2ResourceProperties;
    private static final String SECRET_KEY = "secretKey";
    private static final long EXPIRATION_TIME = 900_000;

    @PostConstruct
    public void init() {
        oAuth2AuthorizationServerProperties = properties;
        oauth2ResourceProperties = resourceProperties;
    }

    /// 生成JWT
    public static String generateToken(String userid) {
        return Jwts.builder()
                .subject(userid)
                .issuer(oAuth2AuthorizationServerProperties.getIssuer())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
//                .signWith(Jwts.SIG.HS256.key().build())
                .compact();
    }

    /// 驗證並解析JWT
//    public static Claims validateToken(String token) {
////        return Jwts.parser()
////                .setSigningKey(SECRET_KEY)
////                .parseClaimsJws(token)
////                .getBody();
//    }
//
//    /// 從Token中獲取用戶名
//    public static String getUsernameFromToken(String token) {
//        return validateToken(token).getSubject().;
//    }
}
