package kr.ejsoft.oauth2.server.handler;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import kr.ejsoft.oauth2.server.model.OAuthUserDetails;

public class AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		ObjectMapper om = new ObjectMapper();


		Map<String, Object> map = new HashMap<String, Object>();
		map.put("success", true);
		map.put("returnUrl", getReturnUrl(request, response));
		
		Object details = authentication.getDetails();
		if(details instanceof OAuthUserDetails) {
			OAuthUserDetails userDetails = (OAuthUserDetails) details;
			map.put("name", userDetails.getName());
			map.put("icon", userDetails.getIcon());
		}
		if(details instanceof UserDetails) {
			UserDetails userDetails = (UserDetails) details;
			map.put("username", userDetails.getUsername());
		}
		
		// {"success" : true, "returnUrl" : "..."}
		String jsonString = om.writeValueAsString(map);

		OutputStream out = response.getOutputStream();
		out.write(jsonString.getBytes());
	}

	/**
	 * 로그인 하기 전의 요청했던 URL을 알아낸다.
	 * 
	 * @param request
	 * @param response
	 * @return
	 */
	private String getReturnUrl(HttpServletRequest request, HttpServletResponse response) {
		RequestCache requestCache = new HttpSessionRequestCache();
		SavedRequest savedRequest = requestCache.getRequest(request, response);
		if (savedRequest == null) {
			return request.getSession().getServletContext().getContextPath();
		}
		return savedRequest.getRedirectUrl();
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
		throws IOException, ServletException {

		ObjectMapper om = new ObjectMapper();
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("success", false);
		map.put("message", exception.getMessage());

		// {"success" : false, "message" : "..."}
		String jsonString = om.writeValueAsString(map);

		OutputStream out = response.getOutputStream();
		out.write(jsonString.getBytes());
	}

}