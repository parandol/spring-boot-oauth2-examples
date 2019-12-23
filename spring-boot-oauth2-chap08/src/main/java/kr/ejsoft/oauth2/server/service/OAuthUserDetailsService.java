package kr.ejsoft.oauth2.server.service;

import java.util.Hashtable;

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

	private static Hashtable<String, OAuthUserDetails> cache = null;

	@Autowired
	@Qualifier("oauthUserDetailsDAO")
	private OAuthUserDetailsDAO dao;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		log.debug("User Name : {}", username);
		OAuthUserDetails user = (cache != null && cache.containsKey(username)) ? cache.get(username) : dao.getUserById(username);
//		OAuthUserDetails user = dao.getUserById(username);
		if (user == null) {
			throw new UsernameNotFoundException(username);
		}

		addCache(username, user);
		
		log.debug("User : {}", user.toString());
		return user;
	}

	private void addCache(String username, OAuthUserDetails user) {
		if(username == null || user == null) return;
		
		synchronized(OAuthUserDetailsService.class) {
			if(cache == null) {
				cache = new Hashtable<String, OAuthUserDetails>();
			}
			
			cache.put(username, user);
		}
	}

	public void removeCache(String username) {
		if(cache != null) {
			synchronized(OAuthUserDetailsService.class) {
				cache.remove(username);
			}
		}
	}
}
