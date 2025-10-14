package com.otd.otd_msa_back_gateway.configuration.jwt;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.otd.otd_msa_back_gateway.configuration.constants.ConstJwt;
import com.otd.otd_msa_back_gateway.configuration.model.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;

import org.springframework.security.core.Authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;

import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Objects;
import java.util.stream.Collectors;


@Slf4j
@Component
@RequiredArgsConstructor
public class TokenAuthenticationFilter implements WebFilter {

    private final ObjectMapper objectMapper;
    private final JwtTokenProvider jwtTokenProvider; // 토큰 파싱/검증 유틸 (게이트웨이용)
    private final ConstJwt constJwt;                 // issuer, 쿠키명, 헤더키 등 설정 보유



    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("!!!!!!!!!!!!!!!!!!!!!!");
        // 요청 정보
        ServerHttpRequest request = exchange.getRequest();
        Authentication authentication = jwtTokenProvider.getAuthentication(request);
        log.info("authentication JSON: {}", authentication);
        if(authentication != null) {
            try {
                UserPrincipal up = (UserPrincipal) authentication.getPrincipal();
                String userId = String.valueOf(up.getSignedUserId());
                String rolesEnumCsv = up.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority) // ROLE_USER, ROLE_ADMIN ...
                        .map(TokenAuthenticationFilter::toEnumName)
                        .filter(Objects::nonNull)
                        .collect(Collectors.joining(","));

                ServerHttpRequest modifiedRequest = request.mutate()
                        .headers(h -> {
                            h.set("X-User-Id", String.valueOf(up.getSignedUserId()));
                            h.set("X-User-Roles", rolesEnumCsv); // ← enum 이름으로 전송
                        })
                        .build();
                // 가공된 Principal 데이터 로그 출력
                log.info("GW add headers -> X-User-Id={}, X-User-Roles={}", userId, rolesEnumCsv);

                ServerWebExchange modifiedExchange = exchange.mutate()
                        .request(modifiedRequest)
                        .build();

                SecurityContext context = new SecurityContextImpl(authentication);

                return chain.filter(modifiedExchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
                        .doOnSuccess(v -> log.info("GW response status -> {}", modifiedExchange.getResponse().getStatusCode()))
                        .doOnError(ex -> log.error("GW pipeline error", ex));
            } catch (Exception e) {
                log.error("Error while processing authentication principal", e);
                //request.setAttribute("exception", e);
            }
        }
        return  chain.filter(exchange)
                .doOnSuccess(v ->
                        log.info("GW response status -> {}", exchange.getResponse().getStatusCode()))
                .doOnError(ex ->
                        log.error("GW pipeline error", ex));
    }

    private static String toEnumName(String authority) {
        String key = authority.startsWith("ROLE_") ? authority.substring(5) : authority; // USER, SOCIAL, ...
        return switch (key) {
            case "USER"   -> "USER_1";
            case "SOCIAL" -> "USER_2";
            case "MANAGER"-> "MANAGER";
            case "ADMIN"  -> "ADMIN";
            default       -> null; // 알 수 없는 권한은 버림(또는 예외)
        };
    }
}



