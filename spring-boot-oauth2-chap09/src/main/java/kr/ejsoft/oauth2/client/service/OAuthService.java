package kr.ejsoft.oauth2.client.service;

import kr.ejsoft.oauth2.client.model.OAuthToken;

public interface OAuthService {

	public OAuthToken requestAccessToken(String oauthServer, String header, String code, String redirect);
	
	public OAuthToken refreshAccessToken(String oauthServer, String header, String refreshToken, String scope);

	void logout(String tokenId, String userName);
}
