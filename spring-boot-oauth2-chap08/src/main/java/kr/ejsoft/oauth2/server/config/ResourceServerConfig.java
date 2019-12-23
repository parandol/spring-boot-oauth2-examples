package kr.ejsoft.oauth2.server.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

import kr.ejsoft.oauth2.server.handler.AuthenticationHandler;

//@Configuration
//@EnableResourceServer
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	private static final Logger log = LoggerFactory.getLogger(ResourceServerConfig.class);

//	@Bean
//	public AuthenticationHandler authenticationHandler() {
//		return new AuthenticationHandler();
//	}
//	
//	@Autowired
//	private AuthenticationHandler authenticationHandler;
//	
//	@Override
//	public void configure(HttpSecurity http) throws Exception {
////		http
////			.csrf().disable()
////			.authorizeRequests().antMatchers("/api/**").authenticated() //.access("#oauth2.hasScope('read_profile')")
////			.anyRequest().permitAll()
////			;
//		
//		http
//		.csrf().disable()
//			.authorizeRequests()
//			.antMatchers("/", "/home", "/js/**", "/css/**", "/img/**", "/favicon.ico").permitAll()
//			.antMatchers("/auth/**").permitAll()
//			.antMatchers("/api/**").authenticated()
////			.antMatchers("/api/**").access("isAuthenticated()")//.authenticated()
//			.anyRequest().authenticated()
//		.and()
//			.formLogin()
////			.loginProcessingUrl("/login")
//			.loginPage("/login").permitAll()
////			.successForwardUrl("/login?success")
////			.failureUrl("/login?failure")
//			.successHandler(authenticationHandler)
//			.failureHandler(authenticationHandler)
//		.and()
//			.logout().permitAll()
//		.and()
//			.httpBasic()
//		;
//	}
}
