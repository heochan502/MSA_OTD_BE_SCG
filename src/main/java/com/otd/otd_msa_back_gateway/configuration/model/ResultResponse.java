package com.otd.otd_msa_back_gateway.configuration.model;


import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ResultResponse<T> {
    private String message;
    private T result;
}
