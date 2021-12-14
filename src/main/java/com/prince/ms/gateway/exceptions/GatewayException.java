package com.prince.ms.gateway.exceptions;

public class GatewayException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	
	private final Integer code;
	
	public GatewayException(Integer code) {
		super();
		this.code = code;
	}
	
	public GatewayException(String message, Integer code) {
		super(message);
		this.code = code;
	}
	
	public Integer getCode() {
		return this.code;
	}
	
}
