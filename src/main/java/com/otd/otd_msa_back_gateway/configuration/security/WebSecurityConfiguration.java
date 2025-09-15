package com.otd.otd_msa_back_gateway.configuration.security;
//Spring Security 세팅


import com.otd.otd_msa_back_gateway.configuration.exception.CustomAuthenticationEntryPoint;
import com.otd.otd_msa_back_gateway.configuration.jwt.TokenAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;


import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration {

    private final TokenAuthenticationFilter tokenAuthenticationFilter;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 1. 인증정보 포함 여부 (쿠키/Authorization 헤더 등)
        configuration.setAllowCredentials(true);

        // 2. 허용할 Origin (출처)
        configuration.setAllowedOriginPatterns(List.of("*"));
        // "*" = 모든 도메인 허용 (보안적으로는 위험 → 실제 운영에서는 특정 도메인만 허용해야 함)

        // 3. 허용할 HTTP 메서드
        configuration.setAllowedMethods(
                Arrays.asList("HEAD", "GET", "POST", "PUT", "PATCH", "DELETE")
        );

        // 4. 허용할 HTTP 헤더
        configuration.setAllowedHeaders(List.of("*"));
        // "*" = 모든 요청 헤더 허용

        // 5. 최종적으로 매핑할 경로 등록
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 모든 경로에 위 규칙 적용

        return source;
    }

    @Bean // 스프링이 메소드 호출을 하고 리턴한 객체의 주소값을 관리한다. (빈등록)
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) throws Exception {
        return http

                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .securityContextRepository(new StatelessWebSessionSecurityContextRepository()) // 세션 사용 안함
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/admin").hasAuthority("ADMIN")
                        .pathMatchers(HttpMethod.DELETE,"/api/admin").hasAuthority("ADMIN")
                        /*.pathMatchers("/api/admin/**").hasRole("ADMIN")*/
//                        .pathMatchers("/api/OTD/user/oauth/**").permitAll() // OAuth 경로 예외 처리
                        .anyExchange().permitAll()
                )
                .cors(corsSpec -> corsConfigurationSource())
                .addFilterAt(tokenAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling(e -> e.authenticationEntryPoint(authenticationEntryPoint))
                .build();


    }

    //https://gose-kose.tistory.com/27
    private static class StatelessWebSessionSecurityContextRepository implements ServerSecurityContextRepository {
        private static final Mono<SecurityContext> EMPTY_CONTEXT = Mono.empty();

        @Override
        public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {return Mono.empty();}

        @Override
        public Mono<SecurityContext> load(ServerWebExchange exchange) {return EMPTY_CONTEXT;}

    }
}
