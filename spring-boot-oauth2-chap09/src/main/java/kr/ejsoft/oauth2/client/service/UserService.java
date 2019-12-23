package kr.ejsoft.oauth2.client.service;

import kr.ejsoft.oauth2.client.model.User;
import kr.ejsoft.oauth2.client.model.OAuthUser;

public interface UserService {

	User loadUser(String userName);
	
	public int insertUser(User user);

	public boolean updateToken(String username, String accessToken, String refreshToken);

	public OAuthUser requestUserInfo(String apiServer, String header, String clientId, String accessToken);
}
