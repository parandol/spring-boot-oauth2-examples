package kr.ejsoft.oauth2.server.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import kr.ejsoft.oauth2.server.dao.OAuthUserDetailsDAO;
import kr.ejsoft.oauth2.server.model.OAuthUserDetails;

@Service("oauthUserDetailsService")
public class OAuthUserDetailsService implements UserDetailsService {
	private static final Logger log = LoggerFactory.getLogger(OAuthUserDetailsService.class);

	@Autowired
	@Qualifier("oauthUserDetailsDAO")
	private OAuthUserDetailsDAO userAuthDAO;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		OAuthUserDetails user = userAuthDAO.getUserById(username);
		if (user == null) {
			throw new UsernameNotFoundException(username);
		}
		log.debug("User : {}", user.toString());
		return user;
	}
}
