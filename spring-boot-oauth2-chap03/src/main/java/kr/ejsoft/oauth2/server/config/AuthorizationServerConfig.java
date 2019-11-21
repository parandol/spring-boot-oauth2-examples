package kr.ejsoft.oauth2.server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);


	/**
	 * Inject the authenticationManager to support password grant type
	 */
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	@Qualifier("oauthTokenStoreService")
	private TokenStore tokenStoreService;

	@Autowired
	@Qualifier("oauthApprovalStoreService")
	private ApprovalStore approvalStore;

	@Autowired
	@Qualifier("oauthCodeService")
	private AuthorizationCodeServices authorizationCodeServices;
	
	@Autowired
	@Qualifier("oauthClientDetailsService")
	private ClientDetailsService clientDetailsService;

	@Autowired
	@Qualifier("oauthUserDetailsService")
	private UserDetailsService userDetailsService;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.tokenStore(tokenStoreService)
			.approvalStore(approvalStore)
			.authorizationCodeServices(authorizationCodeServices)
			.userDetailsService(userDetailsService);
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
}


