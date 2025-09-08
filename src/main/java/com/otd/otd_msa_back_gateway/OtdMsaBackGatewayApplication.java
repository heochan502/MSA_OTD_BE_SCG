package com.otd.otd_msa_back_gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.web.reactive.config.EnableWebFlux;


/*
    라우팅 역할
    - application.yaml

    인증/인가 처리
    - com.green.scg2.configuration.jwt JWT열어보고 시큐리티 연계용
    - com.green.scg2.congfiguration.security 시큐리티 관련 세팅


    (로그인이 되어 있다면, 즉 JWT 가 넘어온다면)
    JwtUser는 JWT안에 담겨져있던 claim을 객체로 변환 때 사용
    UserPrincipal에 JwtUser안에 있는 user_id를 담는다.
    UserPrincipal이 각 서비스 프로젝트에 전달 된다.

    예외 메시지 처리
    - com.green.scg2.configuration.exception 패키지 관련

    글로벌 필터
    - com.green.scg2.configuration.filter 모든 응답처리를 UTF-8로 처리
 */

@ConfigurationPropertiesScan
@SpringBootApplication
@EnableWebFlux

public class OtdMsaBackGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(OtdMsaBackGatewayApplication.class, args);
    }

}
