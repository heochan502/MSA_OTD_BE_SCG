package com.otd.otd_msa_back_gateway.configuration.jwt;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.otd.otd_msa_back_gateway.configuration.constants.ConstJwt;
import com.otd.otd_msa_back_gateway.configuration.util.MyCookieUtils;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Slf4j
@Component
public class JwtTokenProvider {
    private final ObjectMapper objectMapper;
    private final ConstJwt constJwt;
    private final SecretKey secretKey;
    private final MyCookieUtils myCookieUtils;


    public JwtTokenProvider(ObjectMapper objectMapper, ConstJwt constJwt, SecretKey secretKey, MyCookieUtils myCookieUtils)
    {
        this.objectMapper = objectMapper;
        this.constJwt = constJwt;
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(constJwt.getSecretKey())); // 43자 이상
        this.myCookieUtils = myCookieUtils;
    }
    private String getAccessToken(ServerHttpRequest request) {
        return myCookieUtils.getValue(request, constJwt.getAccessTokenCookieName());
    }



}
