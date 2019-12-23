package kr.ejsoft.oauth2.client.service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.client.methods.HttpPost;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import kr.ejsoft.oauth2.client.dao.UserDao;
import kr.ejsoft.oauth2.client.model.User;
import kr.ejsoft.oauth2.client.model.OAuthUser;
import kr.ejsoft.oauth2.client.util.HttpUtil;

@Service
public class UserServiceImpl implements UserService {
	private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
	
	@Autowired
	private UserDao dao;
	
	@Override
	public User loadUser(String userName) {
		return dao.selectUserById(userName);
	}
	
	@Override
	public int insertUser(User user) {
		return dao.insertUser(user);
	}
	
	@Override
	public boolean updateToken(String username, String accessToken, String refreshToken) {
		//
		User user = dao.selectUserById(username);
		user.setAccessToken(accessToken);
		user.setRefreshToken(refreshToken);
		
		dao.insertUser(user);
		return true;
	}

	@Override
	public OAuthUser requestUserInfo(String apiServer, String authorizationHeader, String clientId, String token) {
		OAuthUser user = null;
		try {
			String reqUrl = String.format("%s/api/userinfo", apiServer);
			
			Map<String, String> paramMap = new HashMap<>();
//			paramMap.put("token", token);
//			paramMap.put("clientId", clientId);
			
			HttpPost post = HttpUtil.buildHttpPost(reqUrl, paramMap, authorizationHeader);

			String json = HttpUtil.executeHttp(post);
			Map<String, Object> map = new HashMap<String, Object>();
			map = new ObjectMapper().readValue(json, new TypeReference<Map<Object, Object>>(){});
			
			
//			"error":"invalid_token","error_description":"Access token expired"
			map.get("error");
			map.get("error_description");
			
			
			logger.debug("UserInfo : {}", map);
			user = new OAuthUser();
			user.setUsername((String) map.get("username"));
			user.setName((String) map.get("name"));
			user.setIcon((String) map.get("icon"));
		} catch (JsonGenerationException e) {
			e.printStackTrace();
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return user;
	}
}