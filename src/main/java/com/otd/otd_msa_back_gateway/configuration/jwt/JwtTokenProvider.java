package com.otd.otd_msa_back_gateway.configuration.jwt;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otd.otd_msa_back_gateway.configuration.constants.ConstJwt;
import com.otd.otd_msa_back_gateway.configuration.model.JwtUser;
import com.otd.otd_msa_back_gateway.configuration.model.UserPrincipal;
import com.otd.otd_msa_back_gateway.configuration.util.MyCookieUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Slf4j
@Component
public class JwtTokenProvider { //토큰 생성/파싱/검증
    private final ObjectMapper objectMapper;
    private final ConstJwt constJwt;
    private final SecretKey secretKey;
    private final MyCookieUtils myCookieUtils;

    public JwtTokenProvider(ObjectMapper objectMapper, ConstJwt constJwt, MyCookieUtils myCookieUtils) {
        this.objectMapper = objectMapper;
        this.constJwt = constJwt;
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(constJwt.getSecretKey())); //43자 이상
        this.myCookieUtils = myCookieUtils;
    }

    private String getAccessToken(ServerHttpRequest request) {
        return myCookieUtils.getValue(request, constJwt.getAccessTokenCookieName());
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public JwtUser getJwtUserFromToken(String token) {
        Claims claims = getClaims(token);
        String json = claims.get(constJwt.getClaimKey(), String.class);
        try {
            return objectMapper.readValue(json, JwtUser.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public Authentication getAuthentication(ServerHttpRequest request) {
        try {
            String token = getAccessToken(request);
            log.info("token: {}", token);

            if (token == null || token.isBlank()) {
                log.info("토큰이 비어있습니다. 인증 생략.");
                return null;
            }

            JwtUser jwtUser = getJwtUserFromToken(token);
            log.info("jwtUser: id={}, roles={}",
                    jwtUser != null ? jwtUser.getSignedUserId() : null,
                    jwtUser != null ? jwtUser.getRoles() : null);

            UserPrincipal userPrincipal =
                    new UserPrincipal(jwtUser.getSignedUserId(), jwtUser.getRoles());

            if (userPrincipal.getAuthorities() == null) {
                log.warn("userPrincipal.getAuthorities() == null");
            } else {
                log.info("authorities: {}", userPrincipal.getAuthorities());
            }

            return new UsernamePasswordAuthenticationToken(
                    userPrincipal, null, userPrincipal.getAuthorities());
        } catch (Exception e) {
            log.error("getAuthentication 내부 예외", e);
            // 여기서 null을 리턴하면 호출부 흐름은 계속 진행됨
            return null;
        }}
}
