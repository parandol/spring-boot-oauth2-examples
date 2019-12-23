package kr.ejsoft.oauth2.client.web;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import kr.ejsoft.oauth2.client.model.OAuthToken;
import kr.ejsoft.oauth2.client.model.OAuthResponse;
import kr.ejsoft.oauth2.client.model.User;
import kr.ejsoft.oauth2.client.model.OAuthUser;
import kr.ejsoft.oauth2.client.service.OAuthService;
import kr.ejsoft.oauth2.client.service.UserService;
import kr.ejsoft.oauth2.client.util.HttpUtil;


@Controller
public class OAuthController {
	private static final Logger logger = LoggerFactory.getLogger(OAuthController.class);

	@Value("${oauth.server}")
	private String oauthServer;
	
	@Autowired
	private OAuthService oauthService;
	
	@Autowired
	private UserService userService;

	
	@Value("${oauth.client.id}")
	private String oauthClientId;
	
	@Value("${oauth.client.secret}")
	private String oauthClientSecret;
	
	@Value("${oauth.redirect.uri}")
	private String oauthRedirectUri;

	@Value("${api.server}")
	private String apiServer;


	@RequestMapping(value="/auth/login", method=RequestMethod.GET)
	public String login(HttpServletRequest request) {
		String state = UUID.randomUUID().toString();
		request.getSession().setAttribute("oauthState", state);
		logger.debug("OAuth State : /auth/login, state : {}, Uri : {}", state, oauthRedirectUri);
		
		StringBuilder builder = new StringBuilder();
		builder.append("redirect:");
		builder.append(String.format("%s/oauth/authorize", oauthServer));
		builder.append("?response_type=code");
		builder.append("&client_id=");
		builder.append(oauthClientId);
		builder.append("&redirect_uri=");
		builder.append(oauthRedirectUri);
		builder.append("&scope=");
		builder.append("read_profile");
		builder.append("&state=");
		builder.append(state);
		
		return builder.toString();
	}
	
	@RequestMapping(value="/auth/callback", method=RequestMethod.GET)
	public String callback(HttpServletRequest request, @RequestParam(name="code") String code, @RequestParam(name="state") String state, ModelMap map) {
//		state 체크
		String oauthState = (String)request.getSession().getAttribute("oauthState");
		request.getSession().removeAttribute("oauthState");
		logger.debug("Check, OAuth State : After, oauthState : {}", oauthState);
		logger.debug("Check, OAuth Callback : {}, state : {}", code, state);
		
		if (oauthState == null || oauthState.equals(state) == false) {
			map.put("result", "not matched state");
			return "index";
		}
		
//		코드 체크
		String authorizationBasicHeader = HttpUtil.makeAuthroizationBasicHeader(oauthClientId, oauthClientSecret);
		OAuthToken oauthToken = oauthService.requestAccessToken(oauthServer, authorizationBasicHeader, code, oauthRedirectUri);
		if (oauthToken == null || oauthToken.getError() != null) {
			map.put("result", oauthToken != null ? oauthToken.getError() : "Error");
			return "index";
		}
		logger.debug("Check, OAuth requestAccessToken : oauthToken : {}", oauthToken);

//		String authorizationHeader = HttpUtil.makeAuthroizationTokenHeader(oauthToken.getTokenType(), oauthToken.getAccessToken());
		String authorizationHeader = HttpUtil.makeAuthroizationTokenHeader("Bearer", oauthToken.getAccessToken());
		OAuthUser oauthUser = userService.requestUserInfo(apiServer, authorizationHeader, oauthClientId, oauthToken.getAccessToken());
		if (oauthUser.getError() != null) {
			oauthToken.setError(oauthUser.getError());
			return "index";
		}
		logger.debug("Check, OAuth requestUserInfo : oauthUser : {}", oauthUser);
		
		if(oauthUser.getUsername() != null) {
			User user = userService.loadUser(oauthUser.getUsername());
			if(user == null) {
				user = new User();
				user.set(oauthUser);
				userService.insertUser(user);
			}
			userService.updateToken(oauthUser.getUsername(), oauthToken.getAccessToken(), oauthToken.getRefreshToken());
			request.getSession().setAttribute("user", user);
		} else {
			map.put("result", "User not found.");
			return "index";
		}

		return "redirect:/account";
	}

	@RequestMapping(value="/auth/refresh", method=RequestMethod.GET)
	public Map<String, Object> refresh(HttpServletRequest request, @RequestParam(name="scope", required=false) String scope) {
		Map<String, Object> map = new HashMap<>();
		User user = (User) request.getSession().getAttribute("user");
		if(user == null) {
			map.put("result", "User not found");
			return map;
		}
		
		
//		연장하기
		String authorizationBasicHeader = HttpUtil.makeAuthroizationBasicHeader(oauthClientId, oauthClientSecret);
		OAuthToken oauthToken = oauthService.refreshAccessToken(oauthServer, authorizationBasicHeader, user.getRefreshToken(), scope);
		if (oauthToken == null || oauthToken.getError() != null) {
			if(oauthToken.isRefreshTokenExpired()) {
				map.put("result", oauthToken != null ? oauthToken.getErrorDescription() : "Refresh Token is expired.");
			} else {
				map.put("result", oauthToken != null ? oauthToken.getError() : "Error");
			}
			
			return map;
		}
		
		logger.debug("Check, OAuth requestAccessToken : oauthToken : {}", oauthToken);

//		user.setAccessToken(oauthToken.getAccessToken());
//		user.setRefreshToken(oauthToken.getRefreshToken());
//		userService.insertUser(user);
		userService.updateToken(user.getUsername(), oauthToken.getAccessToken(), oauthToken.getRefreshToken());

		map.put("result", "true");
		map.put("user", user);
		
		request.getSession().setAttribute("user", user);

		return map;
	}
	


	@RequestMapping(value="/auth/logout", method=RequestMethod.GET)
	public String logout(HttpServletRequest request, String tokenId, String username) {
		//
		OAuthResponse response = new OAuthResponse();
		
		logger.debug("\n## logout {}", username);
		User user = userService.loadUser(username);
		if (user == null || user.getAccessToken() == null) {
			// return response;
		}
		
		String savedTokenId = user.getAccessToken();
		logger.debug("Logout savedTokenId, tokenId : '{}', '{}'", savedTokenId, tokenId);
		if (tokenId.equals(savedTokenId) == false) {
			//
//			return response;
		}
		userService.updateToken(username, null, null);
		
//		return response;
		
		String state = UUID.randomUUID().toString();
		request.getSession().setAttribute("oauthState", state);
		
		StringBuilder builder = new StringBuilder();
		builder.append("redirect:");
		builder.append(String.format("%s/logout", oauthServer));
		builder.append("?response_type=code");
		builder.append("&client_id=");
		builder.append(oauthClientId);
		builder.append("&redirect_uri=");
		builder.append(oauthRedirectUri);
		builder.append("&scope=");
		builder.append("read");
		builder.append("&state=");
		builder.append(state);
		
		return builder.toString();
	}
}