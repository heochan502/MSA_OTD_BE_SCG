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
        Claims claims = getClaims(token); // JwtException 던짐
        Object raw = claims.get(constJwt.getClaimKey());

        log.debug("GW claim[{}] type={}, preview={}",
                constJwt.getClaimKey(),
                raw == null ? "null" : raw.getClass().getName(),
                safePreview(String.valueOf(raw)));
        if (raw == null) {
            throw new IllegalArgumentException("JWT claim '" + constJwt.getClaimKey() + "' is missing");
        }

        try {
            if (raw instanceof String s) {
                // JSON 문자열인지 가볍게 확인
                String trimmed = s.trim();
                if ((trimmed.startsWith("{") && trimmed.endsWith("}")) ||
                        (trimmed.startsWith("\"") && trimmed.endsWith("\""))) {
                    return objectMapper.readValue(trimmed, JwtUser.class);
                } else {
                    // JSON이 아닌 평문 → 에러
                    throw new IllegalArgumentException("Claim is not a JSON string: " + safePreview(trimmed));
                }
            } else {
                // 발급 측에서 Map/Pojo로 넣었을 수 있음
                return objectMapper.convertValue(raw, JwtUser.class);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse claim to JwtUser: " + e.getMessage(), e);
        }
    }

    private static String safePreview(String v) {
        if (v == null) return "null";
        return v.length() > 32 ? v.substring(0, 32) + "..." : v;
    }

    private static boolean looksLikeJwt(String token) {
        return token != null && token.matches("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$");
    }

    public Authentication getAuthentication(ServerHttpRequest request) {
        try {
            String token = getAccessToken(request);
            log.info("token(preview): {}", token != null ? token.split("\\.")[0] : "null");

            if (!looksLikeJwt(token)) {
                log.info("토큰이 없거나 JWT 포맷이 아님 → 인증 생략");
                return null;
            }

            JwtUser jwtUser = getJwtUserFromToken(token); // 위에서 방어적으로 파싱
            UserPrincipal principal = new UserPrincipal(jwtUser.getSignedUserId(), jwtUser.getRoles());

            return new UsernamePasswordAuthenticationToken(
                    principal, null, principal.getAuthorities());
        } catch (Exception e) {
            // 게이트웨이에서 500로 터뜨리지 말고 인증만 생략
            log.warn("GW JWT 파싱 실패 → 인증 생략 (사유: {})", e.getMessage());
            return null;
        }
    }
}
