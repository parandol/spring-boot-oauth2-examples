package kr.ejsoft.oauth2.server.config;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import kr.ejsoft.oauth2.server.model.OAuthUserDetails;
import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	//
	private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class);
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests().anyRequest().authenticated()
			.and()
			.formLogin()
			.and()
			.httpBasic();
		
//		makeAuthorizationRequestHeader();
	}

//	@Autowired
//	@Qualifier("oauthUserDetailsService")
//	private UserDetailsService userDetailsService;

	/**
	 * PasswordEncoder: 입력받은 데이터를 암호화한다
	 * 
	 * @return
	 */
	@Bean
//	public PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
//	}
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

////	/**
////	 * 데이터베이스 인증용 Provider
////	 * 
////	 * @return
////	 */
//	@Bean
//	public AuthenticationProvider authenticationProvider() {
////		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
////		authenticationProvider.setUserDetailsService(userDetailsService);
//////		authenticationProvider.setPasswordEncoder(passwordEncoder()); // 패스워드를 암호활 경우 사용한다
////		return authenticationProvider;
////		
////		
////		AuthenticationProvider
//		
//		return new CustomAuthenticationProvider();
//	}

//	/*
//	 * 스프링 시큐리티가 사용자를 인증하는 방법이 담긴 객체.
//	 */
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		/*
//		 * AuthenticationProvider 구현체
//		 */
//		auth.authenticationProvider(authenticationProvider());
////        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
//	}


//	@Bean
//	public UserDetailsService userDetailsService() {
////		PasswordEncoder encoder = passwordEncoder();
////		String password = encoder.encode("pass");
////		log.debug("PasswordEncoder password : [{}] ", password);					// {bcrypt}$2a$10$q6JJMlG7Q7Gt4n/76ydvp.Vk9pWVcTfCQ4NtWyBzNtWOmefYNw/wO
////
////		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
////		manager.createUser(User.withUsername("user").password(password).roles("USER").build());
////		manager.createUser(User.withUsername("admin").password("{noop}pass").roles("USER", "ADMIN").build());
////		return manager;
//		return new OAuthUserDetailsService();
//	}

	private static void makeAuthorizationRequestHeader() {
		String oauthClientId = "client";
		String oauthClientSecret = "secret";

		Encoder encoder = Base64.getEncoder();
		try {
			String toEncodeString = String.format("%s:%s", oauthClientId, oauthClientSecret);
			String authorizationRequestHeader = "Basic " + encoder.encodeToString(toEncodeString.getBytes("UTF-8"));
			log.debug("AuthorizationRequestHeader : [{}] ", authorizationRequestHeader);			// Y2xpZW50OnNlY3JldA==
			
			toEncodeString = String.format("%s:%s", "user", "pass");
			authorizationRequestHeader = "Basic " + encoder.encodeToString(toEncodeString.getBytes("UTF-8"));
			log.debug("Authorization Header : [{}] ", authorizationRequestHeader);			// dXNlcjpwYXNz
		} catch (UnsupportedEncodingException e) {
			log.error(e.getMessage(), e);
		}
	}


	/**
	 * Need to configure this support password mode support password grant type
	 * 
	 * @return
	 * @throws Exception
	 */
	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}

class CustomAuthenticationProvider implements AuthenticationProvider
{

	@Autowired
	@Qualifier("oauthUserDetailsService")
	private UserDetailsService userDetailsService;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) authentication; // 유저가 입력한 정보를 이이디비번으으로만든다.(로그인한 유저아이디비번정보를담는다)

		UserDetails userInfo = userDetailsService.loadUserByUsername(authToken.getName()); // UserDetailsService에서 유저정보를 불러온다.
		if (userInfo == null) {
			throw new UsernameNotFoundException(authToken.getName());
		}

		if (!matchPassword(userInfo.getPassword(), authToken.getCredentials())) {
			throw new BadCredentialsException("not matching username or password");
		}

		List<GrantedAuthority> authorities = (List<GrantedAuthority>) userInfo.getAuthorities();

		return new UsernamePasswordAuthenticationToken(userInfo, null, authorities);
	}

	private boolean matchPassword(String password, Object credentials) {
		return password.equals(credentials);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}