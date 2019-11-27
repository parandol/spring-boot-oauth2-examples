package kr.ejsoft.oauth2.server.service;

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

	@Autowired
	@Qualifier("oauthClientDetailsDAO")
	private OAuthClientDetailsDAO clientDetailsDAO;

	@Override
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		log.debug("Client Id : {}", clientId);
		OAuthClientDetails client = clientDetailsDAO.getClientById(clientId);
		if (client == null) {
			log.debug("Client : null");
			throw new ClientRegistrationException(clientId);
		}
		
		log.debug("Client : {}", client.toString());
		return client;
	}

}
