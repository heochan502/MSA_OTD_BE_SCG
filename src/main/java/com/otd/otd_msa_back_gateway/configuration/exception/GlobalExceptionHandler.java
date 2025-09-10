package com.otd.otd_msa_back_gateway.configuration.exception;

// 내부 (gateway) 에러 처리

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otd.otd_msa_back_gateway.configuration.model.ResultResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;

import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Order(-1)
@RequiredArgsConstructor
@Component
public class GlobalExceptionHandler implements ErrorWebExceptionHandler {
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();

        // 1. 이미 응답이 커밋되었으면 (헤더/바디가 이미 클라이언트로 나감) 그냥 에러 반환
        if (response.isCommitted()) {
            return Mono.error(ex);
        }

        // 2. 응답 Content-Type을 JSON으로 설정
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // 3. ResponseStatusException 이라면 -> 예외에 있는 상태 코드(HttpStatus)를 응답에 세팅
        if (ex instanceof ResponseStatusException) {
            response.setStatusCode(((ResponseStatusException) ex).getStatusCode());
        }

        // 4. 응답 바디 작성
        return response.writeWith(
                Mono.fromSupplier(() -> {
                    DataBufferFactory bufferFactory = response.bufferFactory();
                    try {
                        // 상태코드가 401(UNAUTHORIZED)라면 "로그인해 주세요." 메시지 반환
                        String message = response.getStatusCode() == HttpStatus.UNAUTHORIZED
                                ? "로그인해 주세요."
                                : ex.getMessage();

                        // ResultResponse 객체를 JSON으로 직렬화
                        ResultResponse<?> resultResponse =
                                ResultResponse.<Void>builder().message(message).build();

                        byte[] errorResponse = objectMapper.writeValueAsBytes(resultResponse);

                        // 직렬화된 JSON 바이트를 DataBuffer에 담아서 반환
                        return bufferFactory.wrap(errorResponse);
                    } catch (Exception e) {
                        log.error("error", e);
                        // 에러 발생 시 빈 바이트 배열 반환
                        return bufferFactory.wrap(new byte[0]);
                    }
                })
        );
    }
}
