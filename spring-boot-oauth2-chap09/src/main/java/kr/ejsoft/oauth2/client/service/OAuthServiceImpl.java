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
import org.springframework.stereotype.Service;

import kr.ejsoft.oauth2.client.model.OAuthToken;
import kr.ejsoft.oauth2.client.util.HttpUtil;

@Service("oauthService")
public class OAuthServiceImpl implements OAuthService {
	private static final Logger logger = LoggerFactory.getLogger(OAuthServiceImpl.class);

	

	@Override
	public OAuthToken requestAccessToken(String oauthServer, String header, String code, String redirect) {
		String reqUrl = String.format("%s/oauth/token", oauthServer);
		
		Map<String, String> paramMap = new HashMap<>();
		paramMap.put("grant_type", "authorization_code");
		paramMap.put("redirect_uri", redirect);
		paramMap.put("code", code);
		
		HttpPost post = HttpUtil.buildHttpPost(reqUrl, paramMap, header);
		
		/*
{
    "expires_in": 3599,
    "refresh_token": "eyJhbGciOiJSUzI......4JHR5YcsX4wetCGFA",
    "scope": "read_profile",
    "token_type": "bearer",
    "access_token": "eyJhbGciOiJSUzI1......0admH2iAaf0BVjPoA",
    "jti": "57a02229-8da1-4403-bc95-00103858b984"
}
		 */
		

		OAuthToken token = new OAuthToken();
		try {
			String json = HttpUtil.executeHttp(post);
			Map<String, Object> map = new HashMap<String, Object>();
			map = new ObjectMapper().readValue(json, new TypeReference<Map<Object, Object>>(){});
	
			logger.debug("Token Response : {}", map);
			
			map.get("error");
			map.get("error_description");
	
			token = new OAuthToken();
			token.setTokenType((String) map.get("token_type"));
			token.setAccessToken((String) map.get("access_token"));
			token.setRefreshToken((String) map.get("refresh_token"));
			token.setScope((String) map.get("scope"));
			token.setExpriesIn((Integer) map.get("expires_in"));
//			token.setJti((String) map.get("jti"));
		} catch (JsonGenerationException e) {
			e.printStackTrace();
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		

		return token;
	}

	@Override
	public OAuthToken refreshAccessToken(String oauthServer, String header, String refreshToken, String scope) {
		String reqUrl = String.format("%s/oauth/token", oauthServer);
		
		Map<String, String> paramMap = new HashMap<>();
		paramMap.put("grant_type", "refresh_token");
		paramMap.put("scope", scope);
		paramMap.put("refresh_token", refreshToken);
		
		HttpPost post = HttpUtil.buildHttpPost(reqUrl, paramMap, header);
		
		/*
{
    "expires_in": 3599,
    "refresh_token": "eyJhbGciOiJSUzI......4JHR5YcsX4wetCGFA",
    "scope": "read_profile",
    "token_type": "bearer",
    "access_token": "eyJhbGciOiJSUzI1......0admH2iAaf0BVjPoA",
    "jti": "57a02229-8da1-4403-bc95-00103858b984"
}
		 */
		

		OAuthToken token = new OAuthToken();
		try {
			String json = HttpUtil.executeHttp(post);
			Map<String, Object> map = new HashMap<String, Object>();
			map = new ObjectMapper().readValue(json, new TypeReference<Map<Object, Object>>(){});
	
			logger.debug("Token Response : {}", map);
			
			map.get("error");
			map.get("error_description");
	
			token = new OAuthToken();
			token.setTokenType((String) map.get("token_type"));
			token.setAccessToken((String) map.get("access_token"));
			token.setRefreshToken((String) map.get("refresh_token"));
			token.setScope((String) map.get("scope"));
			token.setExpriesIn((Integer) map.get("expires_in"));
//			token.setJti((String) map.get("jti"));
		} catch (JsonGenerationException e) {
			e.printStackTrace();
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		

		return token;
	}

	@Override
	public void logout(String tokenId, String userName) {

	}
}
