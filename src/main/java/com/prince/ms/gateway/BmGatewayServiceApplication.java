package com.prince.ms.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@EnableZuulProxy
@EnableEurekaClient
@SpringBootApplication
public class BmGatewayServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(BmGatewayServiceApplication.class, args);
	}

}
