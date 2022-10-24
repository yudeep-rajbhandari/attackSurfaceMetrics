package com.yudeep.attacksurface.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestTemplateFactory {

    @Value("${token.project1}")
    private String token;

    @Bean
    public RestTemplateBuilder restTemplateBuilder() {
        return new RestTemplateBuilder();
    }
    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.basicAuthentication(token,"").build();
    }

    @Bean(name = "restbuilder")
    public RestTemplate restTemplate1(RestTemplateBuilder builder) {
        return builder.basicAuthentication("john","yudeep1234").build();
    }
}
