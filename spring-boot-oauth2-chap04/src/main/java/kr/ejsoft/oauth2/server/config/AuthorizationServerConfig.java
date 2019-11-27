package kr.ejsoft.oauth2.server.config;

import java.io.BufferedWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

import javax.sql.DataSource;

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
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import kr.ejsoft.oauth2.server.service.OAuthAuthorizationCodeService;

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

//	@Autowired
//	@Qualifier("oauthAuthorizationCodeService")
//	private AuthorizationCodeServices authorizationCodeServices;
	
	@Bean
	@Primary
	public AuthorizationCodeServices authorizationCodeServices() {
		return new OAuthAuthorizationCodeService();
	}

//	@Bean
//	public AuthorizationCodeServices authorizationCodeServices() {
//		return new OAuthAuthorizationCodeService();
//	}
	
	@Autowired
	@Qualifier("oauthClientDetailsService")
	private ClientDetailsService clientDetailsService;

//	@Autowired
//	@Qualifier("oauthUserDetailsService")
//	private UserDetailsService userDetailsService;
	
//	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//	}
	
	@Bean
	public TokenStore tokenStore() {
		JwtTokenStore tokenStore = new JwtTokenStore(accessTokenConverter());
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
		String pem = writePublicKey(publickey);
		log.info(pem);
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
			.authorizationCodeServices(authorizationCodeServices())
			.approvalStore(approvalStore)
//			.tokenStore(tokenStoreService)
			.tokenStore(tokenStore())
//			.userDetailsService(userDetailsService)
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
	
	public static String writePublicKey(PublicKey key) {
		return writeObject("PUBLIC KEY", key.getEncoded());
	}
	
	private static String writeObject(String type, byte[] bytes){
		final int LINE_LENGTH = 64;
		StringWriter sw = new StringWriter();
		BufferedWriter bw = null;
		try{
			String obj64 = Base64.getEncoder().encodeToString(bytes);
			bw = new BufferedWriter(sw);
			bw.write("-----BEGIN " + type + "-----");
			bw.newLine();
			int index = 0;
			int length = obj64.length() % LINE_LENGTH == 0 ? obj64.length() / LINE_LENGTH : obj64.length() / LINE_LENGTH + 1;
			while(index < length) {
				int start = LINE_LENGTH * index;
				int end = LINE_LENGTH * (index + 1);
				end = end > obj64.length() ? obj64.length() : end;
				
				String sub = obj64.substring(start, end);
				bw.append(sub);
				bw.newLine();
				index++;
			}
			bw.write("-----END " + type + "-----");
			bw.newLine();
		}catch(Exception e){
//			e.printStackTrace();
		} finally {
			if(bw != null){
				try{ bw.flush(); } catch(Exception e) { }
				try{ bw.close(); } catch(Exception e) { }
			}
		}
		
		return sw.toString();
	}
}


