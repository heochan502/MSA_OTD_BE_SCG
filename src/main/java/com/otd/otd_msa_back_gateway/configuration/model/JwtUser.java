package com.otd.otd_msa_back_gateway.configuration.model;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.util.List;

@RequiredArgsConstructor
@Getter
public class JwtUser {
    private final long signedUserId;
    private final List<String> roles;
}
