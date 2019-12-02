package kr.ejsoft.oauth2.server.config;

import java.security.KeyPair;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import kr.ejsoft.oauth2.server.service.OAuthJwtTokenStore;
import kr.ejsoft.oauth2.server.util.OAuthUtil;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);


	/**
	 * Inject the authenticationManager to support password grant type
	 */
	@Autowired
	private AuthenticationManager authenticationManager;

//	@Autowired
//	@Qualifier("oauthTokenStoreService")
//	private TokenStore tokenStoreService;

	@Autowired
	@Qualifier("oauthApprovalStoreService")
	private ApprovalStore approvalStore;

	@Autowired
	@Qualifier("oauthAuthorizationCodeService")
	private AuthorizationCodeServices authorizationCodeServices;

//	@Bean
//	public AuthorizationCodeServices authorizationCodeServices() {
//		return new OAuthAuthorizationCodeService();
//	}
	
	@Autowired
	@Qualifier("oauthClientDetailsService")
	private ClientDetailsService clientDetailsService;

	@Autowired
	@Qualifier("oauthUserDetailsService")
	private UserDetailsService userDetailsService;
	
//	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//	}
	
	@Bean
	public TokenStore tokenStore() {
//		JwtTokenStore tokenStore = new JwtTokenStore(accessTokenConverter());
		JwtTokenStore tokenStore = new OAuthJwtTokenStore(accessTokenConverter());
		tokenStore.setApprovalStore(approvalStore);
		return tokenStore;
	}
	
//	@Bean
//	public JwtAccessTokenConverter accessTokenConverter() {
//		return  new JwtAccessTokenConverter();
//	}
	
//	@Bean
//	public JwtAccessTokenConverter accessTokenConverter() {
//		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//		converter.setSigningKey(signKey);
//		return converter;
//	}
	

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		KeyPair keypair = new KeyStoreKeyFactory(new ClassPathResource("kr.ejsoft.oauth2.server.jks"), "storepass".toCharArray()).getKeyPair("oauth", "keypass".toCharArray());
		converter.setKeyPair(keypair);
		PublicKey publickey = keypair.getPublic();
		
		String authorizationRequestHeader = OAuthUtil.makeAuthorizationRequestHeader("Basic", "client", "secret");
		log.debug("AuthorizationRequestHeader : {} ", authorizationRequestHeader);			// Y2xpZW50OnNlY3JldA==
		
		String pem = OAuthUtil.writePublicKey(publickey);
		log.info("Jwt Verifier Key : {} ", pem);
		
		return converter;
	}
	
//	@Bean
//	@Primary
//	public DefaultTokenServices tokenService() {
//		DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
//		defaultTokenServices.setTokenStore(tokenStore());
//		defaultTokenServices.setSupportRefreshToken(true);
//		return defaultTokenServices;
//	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.authorizationCodeServices(authorizationCodeServices)
			.approvalStore(approvalStore)
//			.tokenStore(tokenStoreService)
			.tokenStore(tokenStore())
			.userDetailsService(userDetailsService)
			.accessTokenConverter(accessTokenConverter());
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//		clients
//			.inMemory()
//			.withClient("client")
////			.secret("{bcrypt}$2a$10$goA9F/Q./Ml8lYvuO1tj6OKA5K6VVM/jmUcdIp1AMzqtXHsuo68/W")		// secret
//			.secret("{noop}secret")		// secret
//			.redirectUris("http://localhost:9000/callback")
////			.authorizedGrantTypes("authorization_code")
////			.authorizedGrantTypes("authorization_code", "implicit")
////			.authorizedGrantTypes("authorization_code", "implicit", "password")
////			.authorizedGrantTypes("authorization_code", "implicit", "password", "client_credentials")
//			.authorizedGrantTypes("authorization_code", "implicit", "password", "client_credentials", "refresh_token")
//			.accessTokenValiditySeconds(120)
//			.refreshTokenValiditySeconds(240)
//			.scopes("read_profile");
		clients.withClientDetails(clientDetailsService);
	}
	
//	@Override
//	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security
//			.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
//			.checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
//		
//		security.tokenKeyAccess("permitAll()")
//			.checkTokenAccess("isAuthenticated()") //allow check token
//			.allowFormAuthenticationForClients();
//	}
}


