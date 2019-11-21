package kr.ejsoft.oauth2.server.config;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private AuthorizationCodeServices authorizationCodeServices;
	
	@Autowired
	private ApprovalStore approvalStore;

	@Autowired
	private TokenStore tokenStore;

	@Bean
	public AuthorizationCodeServices jdbcAuthorizationCodeServices(DataSource dataSource) {
		return new JdbcAuthorizationCodeServices(dataSource);
	}
	
	@Bean
	public ApprovalStore jdbcApprovalStore(DataSource dataSource) {
		return new JdbcApprovalStore(dataSource);
	}

	
	@Bean
	public TokenStore jdbcTokenStore(DataSource dataSource) {
		return new CustomJdbcTokenStore(dataSource);
	}
	
	@Bean
	@Primary
	public ClientDetailsService jdbcClientDetailsService(DataSource dataSource) {
		return new JdbcClientDetailsService(dataSource);
	}

/*
	@Autowired
	@Qualifier("userDetailsService")
	private UserDetailsService userDetailsService;
*/	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.authorizationCodeServices(authorizationCodeServices)
			.tokenStore(tokenStore)
			.approvalStore(approvalStore)
//			.userDetailsService(userDetailsService)
			;
	}
/*
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
			.withClient("client")
//			.secret("{bcrypt}$2a$10$goA9F/Q./Ml8lYvuO1tj6OKA5K6VVM/jmUcdIp1AMzqtXHsuo68/W")		// secret
			.secret("{noop}secret")		// secret
			.redirectUris("http://localhost:9000/callback")
			.authorizedGrantTypes("authorization_code", "implicit", "password", "client_credentials", "refresh_token")
			.accessTokenValiditySeconds(120)
			.refreshTokenValiditySeconds(240)
			.scopes("read_profile");
	}
*/
}


class CustomJdbcTokenStore extends JdbcTokenStore {
	private static final Logger log = LoggerFactory.getLogger(CustomJdbcTokenStore.class);
	public CustomJdbcTokenStore(DataSource dataSource) {
		super(dataSource);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		OAuth2AccessToken accessToken = null;

		try {
			accessToken = new DefaultOAuth2AccessToken(tokenValue);
		} catch (EmptyResultDataAccessException e) {
			if (log.isInfoEnabled()) {
				log.info("Failed to find access token for token " + tokenValue);
			}
		} catch (IllegalArgumentException e) {
			log.warn("Failed to deserialize access token for " + tokenValue, e);
			removeAccessToken(tokenValue);
		}

		return accessToken;
	}
}