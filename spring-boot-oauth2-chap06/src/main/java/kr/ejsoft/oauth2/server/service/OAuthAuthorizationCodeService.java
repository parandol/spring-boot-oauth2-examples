package kr.ejsoft.oauth2.server.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices;
import org.springframework.stereotype.Service;

import kr.ejsoft.oauth2.server.dao.OAuthDAO;
import kr.ejsoft.oauth2.server.model.OAuthAuthenticationCode;

@Service("oauthAuthorizationCodeService")
public class OAuthAuthorizationCodeService implements AuthorizationCodeServices {
	private static final Logger log = LoggerFactory.getLogger(OAuthAuthorizationCodeService.class);

	private RandomValueStringGenerator generator = new RandomValueStringGenerator();

	
	@Autowired
	@Qualifier("oauthDAO")
	private OAuthDAO dao;
	
	@Override
	public String createAuthorizationCode(OAuth2Authentication authentication) {
		String code = generator.generate();
		

		OAuthAuthenticationCode approval = new OAuthAuthenticationCode();
		approval.setCode(code);
		approval.setAuthenticationObject(authentication);
		dao.saveAuthorizationCode(approval);
		
		return code;
	}

	@Override
	public OAuth2Authentication consumeAuthorizationCode(String code)
			throws InvalidGrantException {
		log.debug("OAuthAuthorizationCodeService.consumeAuthorizationCode : {}", code);
		
		OAuth2Authentication auth = null;

		try {
			OAuthAuthenticationCode oauthcode = dao.findAuthenticationByCode(code);
			log.debug("OAuthAuthorizationCodeService : {}", oauthcode);
			auth = oauthcode != null ? oauthcode.getAuthenticationObject() : null;
		} catch (Exception e) {
			return null;
		}

		if (auth != null) {
			dao.deleteAuthorizationCode(code);
		}
		if (auth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + code);
		}
		return auth;
	}
}