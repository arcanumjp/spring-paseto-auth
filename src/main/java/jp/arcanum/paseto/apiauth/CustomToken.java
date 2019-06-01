package jp.arcanum.paseto.apiauth;

import net.aholbrook.paseto.service.Token;

public class CustomToken extends Token {
	
	private String message;
	public String getMessage() {
		return message;
	}
	public Token setMessage(String msg) {
		message = msg;
		return this;
	}
}
