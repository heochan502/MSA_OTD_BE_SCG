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
        // 요청 정보
        ServerHttpRequest request = exchange.getRequest();
        Authentication authentication = jwtTokenProvider.getAuthentication(request);
        log.info("authentication JSON: {}", authentication);
        if(authentication != null) {
            try {
                UserPrincipal up = (UserPrincipal) authentication.getPrincipal();
                String userId = String.valueOf(up.getSignedUserId());
                String rolesCsv = up.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .map(a -> a.startsWith("ROLE_") ? a : "ROLE_" + a) // 안전하게 ROLE_ 프리픽스 보장
                        .collect(Collectors.joining(","));

                ServerHttpRequest modifiedRequest = request.mutate()
                        .headers(h -> {
                            h.set("X-User-Id", userId);
                            h.set("X-User-Roles", rolesCsv);
                        }) // 예: "ROLE_USER,ROLE_ADMIN"
                        .build();
                // 가공된 Principal 데이터 로그 출력
                log.info("GW add headers -> X-User-Id={}, X-User-Roles={}", userId, rolesCsv);

                ServerWebExchange modifiedExchange = exchange.mutate()
                        .request(modifiedRequest)
                        .build();

                SecurityContext context = new SecurityContextImpl(authentication);

                return chain.filter(modifiedExchange)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context)))                        ;
            } catch (Exception e) {
                log.error("Error while processing authentication principal", e);
                //request.setAttribute("exception", e);
            }
        }
        return chain.filter(exchange);
    }
}



