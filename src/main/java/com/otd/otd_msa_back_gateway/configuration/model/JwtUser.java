package com.otd.otd_msa_back_gateway.configuration.model;


import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.List;

@Getter
@RequiredArgsConstructor
public class JwtUser {
    private final Long signedUserId;
    private final List<String> roles;
}
