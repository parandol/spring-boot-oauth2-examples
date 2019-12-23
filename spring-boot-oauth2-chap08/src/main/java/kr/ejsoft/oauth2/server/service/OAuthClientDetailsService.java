package kr.ejsoft.oauth2.server.service;

import java.util.Hashtable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.stereotype.Service;

import kr.ejsoft.oauth2.server.dao.OAuthClientDetailsDAO;
import kr.ejsoft.oauth2.server.model.OAuthClientDetails;

@Service("oauthClientDetailsService")
public class OAuthClientDetailsService implements ClientDetailsService {
	private static final Logger log = LoggerFactory.getLogger(OAuthClientDetailsService.class);

	private static Hashtable<String, OAuthClientDetails> cache = null;
	
	@Autowired
	@Qualifier("oauthClientDetailsDAO")
	private OAuthClientDetailsDAO dao;

	@Override
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		log.debug("Client Id : {}", clientId);
		OAuthClientDetails client = (cache != null && cache.containsKey(clientId)) ? cache.get(clientId) : dao.getClientById(clientId);
//		OAuthClientDetails client = dao.getClientById(clientId);
		if (client == null) {
			log.debug("Client : null");
			throw new ClientRegistrationException(clientId);
		}
		
		addCache(clientId, client);
		
		log.debug("Client : {}", client.toString());
		return client;
	}

	private void addCache(String clientId, OAuthClientDetails details) {
		if(clientId == null || details == null) return;
		
		synchronized(OAuthClientDetailsService.class) {
			if(cache == null) {
				cache = new Hashtable<String, OAuthClientDetails>();
			}
			
			cache.put(clientId, details);
		}
	}

	public void removeCache(String clientId) {
		if(cache != null) {
			synchronized(OAuthClientDetailsService.class) {
				cache.remove(clientId);
			}
		}
	}
}
