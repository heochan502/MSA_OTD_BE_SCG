package com.otd.otd_msa_back_gateway.constants;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@ConfigurationProperties(prefix = "constants.jwt")
@RequiredArgsConstructor
@ToString
public class ConstJwt {
    private final String issuer;
    private final String schema;
    private final String bererFormat;

    private final String claimKey;
    private final String headerKey;
    private final String SecretKey;

    private final String accessTokenCookieName;
    private final String accessTokenCookiePath;
    private final int accessTokenCookieValiditySeconds;
    private final int accessTokenValidityMilliseconds;

    private final String refreshTokenCookieName;
    private final String refreshTokenCookiePath;
    private final int refreshTokenCookieValiditySeconds;
    private final int refreshTokenValidityMilliseconds;
}
