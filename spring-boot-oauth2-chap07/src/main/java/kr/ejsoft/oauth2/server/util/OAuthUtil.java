package kr.ejsoft.oauth2.server.util;

import java.io.BufferedWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.Base64.Encoder;

public class OAuthUtil {


	public static String makeAuthorizationRequestHeader(String type, String clientId, String clientSecret) {
		String authorizationRequestHeader = "";

		Encoder encoder = Base64.getEncoder();
		try {
			String toEncodeString = String.format("%s:%s", clientId, clientSecret);
			authorizationRequestHeader = makeAuthorizationRequestHeader(type, encoder.encodeToString(toEncodeString.getBytes("UTF-8")));
//			log.debug("AuthorizationRequestHeader : [{}] ", authorizationRequestHeader);			// Y2xpZW50OnNlY3JldA==
			
//			toEncodeString = String.format("%s:%s", "user", "pass");
//			authorizationRequestHeader = "Basic " + encoder.encodeToString(toEncodeString.getBytes("UTF-8"));
//			log.debug("Authorization Header : [{}] ", authorizationRequestHeader);			// dXNlcjpwYXNz
		} catch (UnsupportedEncodingException e) {
//			log.error(e.getMessage(), e);
		}
		
		return authorizationRequestHeader;
	}

	public static String makeAuthorizationRequestHeader(String type, String value) {
		return String.format("%s %s", type, value);
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
	
	public static Set<String> toSet(String data) {
		if(data == null) return null;
		String[] arr = data.split(",");
		if(arr != null && arr.length > 0) {
			Set<String> set = new HashSet<>();
//			Collections.addAll(set, arr);
			
			for(String e : arr) {
				if(e == null || "".equals(e)) continue;
				set.add(e.trim());
			}
			return set;
		}
		return null;
	}
	
	public static String[] toArray(Set<String> set) {
		if(set == null) return null;
		return set.toArray(new String[set.size()]);
	}
}
