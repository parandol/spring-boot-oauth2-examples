package kr.ejsoft.oauth2.server.web;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import kr.ejsoft.oauth2.server.model.OAuthClientDetails;
import kr.ejsoft.oauth2.server.model.OAuthUserDetails;
import kr.ejsoft.oauth2.server.util.OAuthUtil;

@Controller
@SessionAttributes("authorizationRequest")
public class AuthController {
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	
	@Autowired
	@Qualifier("oauthClientDetailsService")
	private ClientDetailsService clientDetailsService;

	@Autowired
	@Qualifier("oauthUserDetailsService")
	private UserDetailsService userDetailsService;

	@RequestMapping(value="/", method=RequestMethod.GET)
	public ModelAndView home() {
		logger.debug("Home : ");
		ModelAndView mav = new ModelAndView();
		mav.addObject("message", "Home...");
		mav.setViewName("index");
		return mav;
	}
	

	@RequestMapping(value="/login", method=RequestMethod.GET)
	public ModelAndView login(HttpServletRequest request, @RequestParam Map<String, String> parameters, Map<String, ?> model,
			SessionStatus sessionStatus, Principal principal1) {
//
//		AuthorizationRequest authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);
//    Set<String> responseTypes = authorizationRequest.getResponseTypes();try {
// Create ClientDtails
//        ClientDetails client = getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());

//		HttpSession session = request.getSession();
//		SavedRequest savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
//
//		String clientid = null;
//		if(savedRequest != null) { 
//			String[] clientids = savedRequest.getParameterValues("client_id");
//			clientid = (clientids != null && clientids.length > 0) ? clientids[0]: null;
//			
//			logger.debug("Clientid in savedRequest : {}", clientid);				// Clientid : client
//		}
		//		ClientDetails client = getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());
		
		
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		String currentPrincipalName = authentication.getName();
//		
//		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//		
//		Object principal = authentication.getPrincipal();
//		logger.debug("Principal : {}", principal);				// Principal : admin
//		logger.debug("Authorities : {}", authorities);			// Authorities : [user, admin]
//		
//		if(authentication instanceof OAuth2Authentication) {
//			clientid = ((OAuth2Authentication) authentication).getOAuth2Request().getClientId();
//			Set<String> scops = ((OAuth2Authentication) authentication).getOAuth2Request().getScope();
//			logger.debug("Scopes : {}", scops);				// Scopes : [read_profile]
//		}
//
//		logger.debug("Login..... {}, {}", currentPrincipalName, clientid);
		
		ModelAndView mav = new ModelAndView();
		mav.setViewName("login");
		return mav;
	}

	@RequestMapping(value="/auth/client", method=RequestMethod.GET)
	@ResponseBody
	public Map<String, Object> client(HttpServletRequest request) {
		HttpSession session = request.getSession();
		SavedRequest savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");

		Map<String, Object> map = new HashMap<String, Object>();
		String clientId = null;
		if(savedRequest != null) { 
			String[] clientIds = savedRequest.getParameterValues("client_id");
			clientId = (clientIds != null && clientIds.length > 0) ? clientIds[0]: null;

			logger.debug("Clientid in savedRequest : {}", clientId);				// Clientid : client
			logger.debug("RedirectUrl in savedRequest : {}", savedRequest.getRedirectUrl());
		}

//		      client: {
//		        icon : "https://library.kissclipart.com/20191016/rqe/kissclipart-child-icon-happiness-icon-family-icon-4509ca3f41157322.png",
//		        name : "Client",
//		        desc : "Description... Description... Description... Description... Description... Description... Description... Description... ",
//		        authorization : [
//		          "read_profile",
//		          "write_article",
//		          "read_username",
//		          "read_email"
//		        ]
//		      },

		if(clientId != null && !"".equals(clientId)) {
			ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
			if(client != null) {
				if(client instanceof OAuthClientDetails) {
					OAuthClientDetails details = (OAuthClientDetails) client;
					map.put("icon", details.getIcon());
					map.put("name", details.getName());
					map.put("desc", details.getDescription());
				} else {
					map.put("icon", null);
					map.put("name", client.getClientId());
					map.put("desc", client.getClientId());
				}
				
				String[] dbscope = OAuthUtil.toArray(client.getScope());
				String[] scope = savedRequest.getParameterValues("scope");

				map.put("authorization", merge(dbscope, scope));
				map.put("code", "200");
				map.put("message", "success");
			} else {
				map.put("code", "404");
				map.put("message", "client not found.");
			}
//			map.put("icon", "https://library.kissclipart.com/20191016/rqe/kissclipart-child-icon-happiness-icon-family-icon-4509ca3f41157322.png");
//			map.put("name", "Client Name by Server");
//			map.put("desc", "클라이언트에 대한 설명이 들어갑니다. 어떤 용도의 클라이언트인지 확인이 가능합니다.");
//			map.put("authorization", new String[] {"read_profile", "write_article", "write_article", "read_email", "read_username"});
		} else {
			map.put("code", "403");
			map.put("message", "client id not found.");
		}
		

		
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		String currentPrincipalName = authentication.getName();
//		
//		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//		
//		Object principal = authentication.getPrincipal();
//		logger.debug("Principal : {}", principal);				// Principal : admin
//		logger.debug("Authorities : {}", authorities);			// Authorities : [user, admin]
//		
//		logger.debug("Client Id : {}, {}", clientid, currentPrincipalName);

		return map;
	}
	
	private String[] merge(String[] all, String[] scope) {
		if(all == null || scope == null || all.length == 0 || scope.length == 0) return null;
		List<String> ret = new ArrayList<String>();
		for(String sco : scope) {
			for(String item : all) {
				if(sco.trim().equals(item.trim())) {
					ret.add(sco.trim());
					break;
				}
			}
		}
		return ret.toArray(new String[ret.size()]);
	}

	
//	@PreAuthorize("#oauth2.hasScope('read_profile')")
//	@PreAuthorize("hasAuthority('ROLE_USER')")
//	@PreAuthorize("hasRole('ROLE_USER')")
//	@PreAuthorize("hasAuthority('user')")
//	@PreAuthorize("isAuthenticated() and (( #user.name == principal.name ) or hasRole('ROLE_ADMIN'))")
//	@PostAuthorize("isAuthenticated() and (( returnObject.name == principal.name ) or hasRole('ROLE_ADMIN'))")
//	@PostAuthorize("isAuthenticated() and hasRole('ROLE_ADMIN')")
//	@Secured("ROLE_ADMIN")
//	@RequestMapping(value="/api/users", method=RequestMethod.GET)
//	@ResponseBody
	@RequestMapping(value="/api/userinfo", method=RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> userinfo() {
		// Build some dummy data to return for testing
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
		
		Object principal = auth.getPrincipal();
		logger.debug("Principal : {}", principal);				// Principal : admin
		logger.debug("Authorities : {}", authorities);			// Authorities : [user, admin]
		if(auth instanceof OAuth2Authentication) {
			Set<String> scops = ((OAuth2Authentication) auth).getOAuth2Request().getScope();
			logger.debug("Scopes : {}", scops);					// Scopes : [read_profile]
		}

		UserDetails details = null;
		Map<String, Object> map = new HashMap<String, Object>();
		if(principal instanceof String) {
			map.put("name", (String) principal);
			map.put("username", (String) principal);
			UserDetails user = userDetailsService.loadUserByUsername((String) principal);
			if(user != null) {
				details = user;
			}
		}
		if(principal instanceof OAuthUserDetails) {
			details = (OAuthUserDetails) principal;
		} else if(principal instanceof UserDetails) {
			details = (UserDetails) principal;
		}

		if(details != null && details.getUsername() != null) {
			if(details instanceof OAuthUserDetails) {
				OAuthUserDetails userDetails = (OAuthUserDetails) details;
				map.put("name", userDetails.getName());
				map.put("icon", userDetails.getIcon());
			}
			if(details instanceof UserDetails) {
				UserDetails userDetails = (UserDetails) details;
				map.put("username", userDetails.getUsername());
			}
			
			logger.debug("UserInfo : {}", map);
		}
		return map;
	}
}
