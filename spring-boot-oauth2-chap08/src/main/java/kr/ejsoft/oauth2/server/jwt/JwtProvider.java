package kr.ejsoft.oauth2.server.jwt;

import io.jsonwebtoken.*;
import kr.ejsoft.oauth2.server.service.OAuthApprovalStoreService;
import kr.ejsoft.oauth2.server.util.PKIUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.PublicKey;

@Component
public class JwtProvider {
	private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

//    @Value("${hendisantika.app.jwtSecret}")
//    private String jwtSecret;
//
//    @Value("${hendisantika.app.jwtExpiration}")
//    private int jwtExpiration;
//    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;
//    
//    public String generateJwtToken(Authentication authentication) {
//
//        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();
//
//        return Jwts.builder()
//                .setSubject((userPrincipal.getUsername()))
//                .setIssuedAt(new Date())
//                .setExpiration(new Date((new Date()).getTime() + jwtExpiration))
//                .signWith(SignatureAlgorithm.HS512, jwtSecret)
//                .compact();
//    }
	public PublicKey loadKey() {
		PublicKey publicKey = null;
		try {
			Resource resource = new ClassPathResource("kr.ejsoft.oauth2.publickey.txt");
			publicKey = PKIUtil.loadPublicKey(resource.getFile().getAbsolutePath());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return publicKey;

//		String publickey = null;
//		try {
//			publickey = asString(resource);
//			
//			logger.info("Jwt Verifier Key : {} ", publickey);
//			
//		} catch(final IOException e) {
//			throw new RuntimeException(e);
//		}
//		
//		
//		return publickey;
	}
	
	public static String asString(Resource resource) throws IOException {
		Reader reader = new InputStreamReader(resource.getInputStream(), "UTF-8");
		return FileCopyUtils.copyToString(reader);
	}

	public String getUserNameFromJwtToken(String token) {
		JwtParser parser = Jwts.parser().setSigningKey(loadKey());
		Jws<Claims> claims = parser.parseClaimsJws(token);
		Claims body = claims.getBody();
		logger.debug("body : {}", body.entrySet());
		logger.debug("body.getSubject : {}", body.getSubject());
		logger.debug("body.get(user_name) : {}", body.get("user_name"));
		return (String) body.get("user_name");
	}

	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(loadKey()).parseClaimsJws(authToken);
			return true;
//        } catch (SignatureException e) {
//            logger.error("Invalid JWT signature -> Message: {} ", e);
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token -> Message: {}", e.getMessage());
		} catch (ExpiredJwtException e) {
			logger.error("Expired JWT token -> Message: {}", e.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.error("Unsupported JWT token -> Message: {}", e.getMessage());
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims string is empty -> Message: {}", e.getMessage());
		}

		return false;
	}
}