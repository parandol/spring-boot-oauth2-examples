package kr.ejsoft.oauth2.server.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import kr.ejsoft.oauth2.server.util.SerializableObjectConverter;

public class OAuthAccessToken {
	private static final Logger log = LoggerFactory.getLogger(OAuthAccessToken.class);
//	@Id
	private String id;
	private String tokenId;
//	private OAuth2AccessToken token;
	private String token;
	private String authenticationId;
	private String username;
	private String clientId;
	private String authentication;
	private String refreshToken;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public String getToken() {
		return token;
	}
	public OAuth2AccessToken getTokenObject() {
//		log.debug("Access Token 111 : {}", token);
		return token != null ? SerializableObjectConverter.deserializeAccessToken(token) : null;
	}
	
	public String getAuthenticationId() {
		return authenticationId;
	}

	public void setAuthenticationId(String authenticationId) {
		this.authenticationId = authenticationId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public void setTokenObject(OAuth2AccessToken token) {
		this.token = SerializableObjectConverter.serializeAccessToken(token);
//		log.debug("Access serializedToken : {}", token);
	}

	public void setToken(String token) {
//		log.debug("Access Token 222 : {}", token);
		this.token = token;
	}
	
	public OAuth2Authentication getAuthenticationObject() {
		return SerializableObjectConverter.deserializeAuthentication(authentication);
	}

	public void setAuthenticationObject(OAuth2Authentication authentication) {
		this.authentication = SerializableObjectConverter.serializeAuthentication(authentication);
	}
	
	public String getAuthentication() {
		return authentication;
	}

	public void setAuthentication(String authentication) {
		this.authentication = authentication;
	}
}