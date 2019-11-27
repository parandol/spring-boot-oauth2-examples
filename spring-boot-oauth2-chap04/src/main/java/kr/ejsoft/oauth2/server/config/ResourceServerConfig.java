package kr.ejsoft.oauth2.server.config;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.FileCopyUtils;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests().anyRequest().authenticated()
			.and()
			.requestMatchers().antMatchers("/api/**");
	}
	
//	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

//	@Primary
//	@Bean
//	public RemoteTokenServices tokenService() {
//		RemoteTokenServices tokenService = new RemoteTokenServices();
//		tokenService.setCheckTokenEndpointUrl("http://localhost:8080/spring-security-oauth-server/oauth/check_token");
//		tokenService.setClientId("foo");
//		tokenService.setClientSecret("bar");
//		return tokenService;
//	}
	
//	
//	@Bean
//	public JwtAccessTokenConverter accessTokenConverter() {
//		return new JwtAccessTokenConverter();
//	}
//	
//	@Bean
//	public JwtAccessTokenConverter accessTokenConverter() {
//		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//		converter.setSigningKey(signKey);
//		return converter;
//	}
//	
//	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		Resource resource = new ClassPathResource("kr.ejsoft.oauth2.publickey.txt");
		String publickey = null;
		try {
			publickey = asString(resource);
		} catch(final IOException e) {
			throw new RuntimeException(e);
		}
		
		converter.setVerifierKey(publickey);
		return converter;
	}
	
	public static String asString(Resource resource) throws IOException {
		Reader reader = new InputStreamReader(resource.getInputStream(), "UTF-8");
		return FileCopyUtils.copyToString(reader);
	}
}
