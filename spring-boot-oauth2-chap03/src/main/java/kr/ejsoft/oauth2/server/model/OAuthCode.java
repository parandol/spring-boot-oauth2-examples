package kr.ejsoft.oauth2.server.model;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import kr.ejsoft.oauth2.server.util.SerializableObjectConverter;

public class OAuthCode {
	private String code;
	private String authentication;
	public String getCode() {
		return code;
	}
	public void setCode(String code) {
		this.code = code;
	}
	public String getAuthentication() {
		return authentication;
	}
	public void setAuthentication(String authentication) {
		this.authentication = authentication;
	}
	
	public OAuth2Authentication getAuthenticationObject() {
		return SerializableObjectConverter.deserializeAuthentication(authentication);
	}

	public void setAuthenticationObject(OAuth2Authentication authentication) {
		this.authentication = SerializableObjectConverter.serializeAuthentication(authentication);
	}
	
}
