package com.otd.otd_msa_back_gateway.configuration.security;
//Spring Security 세팅


import com.otd.otd_msa_back_gateway.configuration.exception.CustomAuthenticationEntryPoint;
import com.otd.otd_msa_back_gateway.configuration.jwt.TokenAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.SecurityContext;
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
public class WebSecurityConfiguration  {
    private final Environment environment;
    private final TokenAuthenticationFilter tokenAuthenticationFilter;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        String[] activeProfiles = environment.getActiveProfiles();

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);

        if(Arrays.asList(activeProfiles).contains("prod")) {
            configuration.addAllowedOrigin("https://greenart.n-e.kr");
        } else {
            configuration.setAllowedOriginPatterns(List.of("*"));
        }
        configuration.setAllowedMethods(
                Arrays.asList("HEAD", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean // 스프링이 메소드 호출을 하고 리턴한 객체의 주소값을 관리한다. (빈등록)
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http)  throws Exception {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)// BE - csrf라는 공격이 있는데 공격을 막는 것이 기본으로 활성화 되어 있는데
                // 세션을 이용한 공격이다. 세션을 어차피 안 쓰니까 비활성화
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)  //시큐리티가 제공해주는 인증 처리 -> 사용 안 함
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable) //시큐리티가 제공해주는 인증 처리 -> 사용 안 함
                .securityContextRepository(new StatelessWebSessionSecurityContextRepository()) // 세션 사용 안함
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/admin").hasAuthority("ADMIN")
                        .pathMatchers(HttpMethod.DELETE,"/api/admin").hasAuthority("ADMIN")
                        .anyExchange().permitAll()
                )
                .cors(corsConfigurer -> corsConfigurer.configurationSource(corsConfigurationSource())) // ⭐️⭐️⭐️
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