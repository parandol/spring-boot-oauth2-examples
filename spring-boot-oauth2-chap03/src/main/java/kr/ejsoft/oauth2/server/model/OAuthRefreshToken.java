package kr.ejsoft.oauth2.server.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.springframework.data.annotation.Id;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import kr.ejsoft.oauth2.server.util.SerializableObjectConverter;

public class OAuthRefreshToken {
	private static final Logger log = LoggerFactory.getLogger(OAuthRefreshToken.class);

//	@Id
	private String id;
	private String tokenId;
//	private OAuth2RefreshToken token;
	private String token;
	private String authentication;
	
	

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

	public void setToken(String token) {
//		log.debug("Refresh Token 222 : {}", token);
//		this.token = SerializableObjectConverter.deserializeRefreshToken(token);
		this.token = token;
	}
	
	public OAuth2RefreshToken getTokenObject() {
		return token != null ? SerializableObjectConverter.deserializeRefreshToken(token) : null;
	}

	public void setTokenObject(OAuth2RefreshToken token) {
//		this.token = token;
		this.token = SerializableObjectConverter.serializeRefreshToken(token);
//		log.debug("Refresh serializedToken : {}", token);
	}

	public OAuth2Authentication getAuthenticationObject() {
		return SerializableObjectConverter.deserializeAuthentication(authentication);
	}

	public void setAuthenticationObject(OAuth2Authentication authentication) {
		this.authentication = SerializableObjectConverter.serializeAuthentication(authentication);
	}

	public String getAuthentication() {
		return this.authentication;
	}

	public void setAuthentication(String authentication) {
		this.authentication = authentication;
	}
}
