package com.otd.otd_msa_back_gateway.configuration.util;

import io.netty.handler.codec.http.cookie.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
public class MyCookieUtils {

    //Req header에서 내가 원하는 쿠키를 찾는 메소드
    public String getValue(ServerHttpRequest req, String key)
    {
        List<HttpCookie> cookies = req.getCookies().get(key);
        if (cookies != null || cookies.isEmpty()) {
            return null;
        }
        return cookies.get(0).getValue();
    }

}
