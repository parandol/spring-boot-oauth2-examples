package kr.ejsoft.oauth2.server.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

//import com.nprotect.common.cipher.asn1.ASN1EncodableVector;
//import com.nprotect.common.cipher.asn1.ASN1InputStream;
//import com.nprotect.common.cipher.asn1.ASN1OutputStream;
//import com.nprotect.common.cipher.asn1.ASN1Sequence;
//import com.nprotect.common.cipher.asn1.DERInteger;
//import com.nprotect.common.cipher.asn1.DERSequence;
//import com.nprotect.common.cipher.asn1.pkcs.PrivateKeyInfo;
//import com.nprotect.common.cipher.asn1.x509.DSAParameter;

public class PKIUtil {
/*
	public static KeyPair loadPrivateKey(String path, final String password) throws Exception {
		KeyPair keyPair = null;
//		try{
//			System.out.println(readPlainTextFile(path));
			PEMParser parser = new PEMParser(new StringReader(readPlainTextFile(path)));
			Object object = parser.readObject();
			PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			if (object instanceof PEMEncryptedKeyPair) {
//				System.out.println("Encrypted key - we will use provided password");
				keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
			} else {
//				System.out.println("Unencrypted key - no password needed");
				keyPair = converter.getKeyPair((PEMKeyPair) object);
			}

//		}catch(Exception e){
//			e.printStackTrace();
//		}
		return keyPair;
	}

*/
	public static Certificate loadCertificate(String path) throws Exception {
		Certificate cert = null;
//		try{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			FileInputStream fis1 = new FileInputStream(path);
			cert = certFactory.generateCertificate(fis1);
			fis1.close();
//		}catch(Exception e){
//			e.printStackTrace();
//		}
		return cert;
	}

	public static Certificate parseCertificate(String cert) throws Exception{
		Certificate certificate = null;
		try{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream bai = new ByteArrayInputStream(cert.getBytes());
			certificate = certFactory.generateCertificate(bai);
			bai.close();
		}catch(Exception e){
//			e.printStackTrace();
		}
		return certificate;
	}
/*
	public static PublicKey parsePublicKey(String keystr) throws Exception {
		PublicKey publicKey = null;
//		try{
			PEMParser parser = new PEMParser(new StringReader(keystr));
			Object object = parser.readObject();
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			if (object instanceof SubjectPublicKeyInfo){
				publicKey = converter.getPublicKey((SubjectPublicKeyInfo)object);
			}
//		}catch(Exception e){
//			e.printStackTrace();
//		}
		return publicKey;
	}
	
	
	public static Certificate loadCaCertificate(String path) throws Exception{
		Certificate cert = null;
		try{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			FileInputStream fis1 = new FileInputStream(path);
			cert = certFactory.generateCertificate(fis1);
			fis1.close();
		}catch(Exception e){
			e.printStackTrace();
		}
		return cert;
	}

	public static Collection loadCaCertificates(String path) throws Exception{
		Collection certs = null;
		try{
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			FileInputStream fis1 = new FileInputStream(path);
			certs = certFactory.generateCertificates(fis1);
			fis1.close();
		}catch(Exception e){
			e.printStackTrace();
		}
		return certs;
	}

	public static String readPlainTextFile( String path ) throws Exception {
		BufferedReader reader = new BufferedReader(new FileReader(path));
		String line = null;
		StringBuilder stringBuilder = new StringBuilder();
		String ls = System.getProperty("line.separator");

		while ((line = reader.readLine()) != null) {
			stringBuilder.append(line);
			stringBuilder.append(ls);
		}
		return stringBuilder.toString();
	}


	
	public static void printCertificate(List<X509Certificate> x509certs) throws Exception {
		for(X509Certificate x509cert:x509certs){
			printCertificate(x509cert);
//			System.out.println("\t----------------------------");
		}
		
	}
	public static void printCertificate(X509Certificate x509cert) throws Exception {
//		try{
			String dn = x509cert.getSubjectX500Principal().getName();
			LdapName ldapDN = new LdapName(dn);
			for(Rdn rdn: ldapDN.getRdns()) {
			    System.out.println(rdn.getType() + " -> " + rdn.getValue());
			}
//		}catch(Exception e){
//			e.printStackTrace();
//		}
	}
*//*
	public static void writeCertificate(Certificate cert, String path) throws Exception {
//		try{
			BufferedWriter bw = new BufferedWriter( new FileWriter(path));
			PEMWriter writer = new PEMWriter(bw);
			writer.writeObject(cert);
			writer.flush();
			writer.close();
//		}catch(Exception e){
//			e.printStackTrace();
//		}
	}
	
	public static String writeCertificate(Certificate cert) throws Exception {
		StringWriter sw = new StringWriter();
//		try{
			BufferedWriter bw = new BufferedWriter(sw);
			PEMWriter writer = new PEMWriter(bw);
			writer.writeObject(cert);
			writer.flush();
			writer.close();
//		}catch(Exception e){
//			e.printStackTrace();
//		}
		return sw.toString();
	}
	*/

/*
	public static void writePublicKey(PublicKey key, String path) throws Exception {
//		try{
			BufferedWriter bw = new BufferedWriter( new FileWriter(path));
			PEMWriter writer = new PEMWriter(bw);
			writer.writeObject(key);
			writer.flush();
			writer.close();
//		}catch(Exception e){
//			e.printStackTrace();
//		}
	}
	*/

	public static String writePublicKey(PublicKey key) {
		return writeObject("PUBLIC KEY", key.getEncoded());
	}
	
	public static PublicKey loadPublicKey(String filepath) throws Exception {
		byte[] encoded = loadObject("PUBLIC KEY", filepath);
//		String pubstr = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a06e8363a9da248d179ba43bbabf4d73ef95718c0f5c67fabad6bf3b11b3ea1158e103b2f227afffa00ec8a5c7593e0d99e274b8671eec44ed066def2c37b256bc7b1e2fa7fae685d17e13c8bd810770ed6b8567395215b492cd1f2541d85dd098adab1cf048f4326c380cd4b06d5ab4a7c01834da597974f56cdca68bb56276091fc14a5f8d649ce78849de3995f136c07d289fec850cdb41c45944b131bd7a6c347b1c60612dc44027a9c910b171d9559f492e9d3cb14becedb5b448fed6b78b41de290e535a718f4f0c7f817eff8cab032c6284db3d64ce3e978e479d6289784294c20daec5eef271b9124569e6744857fcfe8968843b83607764a96a2c9f0203010001";
//		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(StringUtil.hexDecode(pubstr));
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
		KeyFactory keyFact1 = KeyFactory.getInstance("RSA");
		return keyFact1.generatePublic(pubKeySpec);
	}

	
	public static PublicKey parsePublicKey(String contents) throws Exception {
		return parsePublicKey("PUBLIC KEY", contents);
	}
	public static PublicKey parsePublicKey(String type, String contents) throws Exception {
		byte[] encoded = parseObject(type, contents);
//		String pubstr = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a06e8363a9da248d179ba43bbabf4d73ef95718c0f5c67fabad6bf3b11b3ea1158e103b2f227afffa00ec8a5c7593e0d99e274b8671eec44ed066def2c37b256bc7b1e2fa7fae685d17e13c8bd810770ed6b8567395215b492cd1f2541d85dd098adab1cf048f4326c380cd4b06d5ab4a7c01834da597974f56cdca68bb56276091fc14a5f8d649ce78849de3995f136c07d289fec850cdb41c45944b131bd7a6c347b1c60612dc44027a9c910b171d9559f492e9d3cb14becedb5b448fed6b78b41de290e535a718f4f0c7f817eff8cab032c6284db3d64ce3e978e479d6289784294c20daec5eef271b9124569e6744857fcfe8968843b83607764a96a2c9f0203010001";
//		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(StringUtil.hexDecode(pubstr));
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
		KeyFactory keyFact1 = KeyFactory.getInstance("RSA");
		return keyFact1.generatePublic(pubKeySpec);
	}

/*
	public static void writePrivateKey(PrivateKey key, String path) throws Exception {
//		try{
			BufferedWriter bw = new BufferedWriter( new FileWriter(path));
			PEMWriter writer = new PEMWriter(bw);
			writer.writeObject(key);
			writer.flush();
			writer.close();
//		}catch(Exception e){
//			e.printStackTrace();
//		}
	}
	
	public static String writePrivateKey(PrivateKey key) throws Exception {
		StringWriter sw = new StringWriter();
//		try{
			BufferedWriter bw = new BufferedWriter(sw);
			PEMWriter writer = new PEMWriter(bw);
			writer.writeObject(key);
			writer.flush();
			writer.close();
//		}catch(Exception e){
//			e.printStackTrace();
//		}
		return sw.toString();
	}
*/
	public static String writePrivateKey(PrivateKey key) {
		//return writeObject("RSA PRIVATE KEY", key.getEncoded());			// PKCS#1
		return writeObject("PRIVATE KEY", key.getEncoded());			// PKCS#8
	}
	
	public static String writePrivateKey(String type, PrivateKey key) {
		//return writeObject("RSA PRIVATE KEY", key.getEncoded());			// PKCS#1
		return writeObject(type, key.getEncoded());			// PKCS#8
	}
	
	public static PrivateKey loadPrivateKey(String filepath) throws Exception {
		// byte[] encoded = loadObject("RSA PRIVATE KEY", filepath);			// PKCS#1
		byte[] encoded = loadObject("PRIVATE KEY", filepath);			// PKCS#8
//		String pristr = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a06e8363a9da248d179ba43bbabf4d73ef95718c0f5c67fabad6bf3b11b3ea1158e103b2f227afffa00ec8a5c7593e0d99e274b8671eec44ed066def2c37b256bc7b1e2fa7fae685d17e13c8bd810770ed6b8567395215b492cd1f2541d85dd098adab1cf048f4326c380cd4b06d5ab4a7c01834da597974f56cdca68bb56276091fc14a5f8d649ce78849de3995f136c07d289fec850cdb41c45944b131bd7a6c347b1c60612dc44027a9c910b171d9559f492e9d3cb14becedb5b448fed6b78b41de290e535a718f4f0c7f817eff8cab032c6284db3d64ce3e978e479d6289784294c20daec5eef271b9124569e6744857fcfe8968843b83607764a96a2c9f020301000102820100322579123cf43fba8e678af55491195fa4c2bca43fe4ed6774e14d12e49cad0c5110bc7c41aee01771eb4d126c765bac1aaeab373c9c70d3b696ece3f6994e38485fdf769bf613fa3e1a3f8ade99273f4826f4a2e84add17fd4efa6e45dfa0ab641ddcbf85e7f7d48ef91221a527f95340a00db0ef934a20a1da2e3a2caf3ca013d49db77e7494fed13eba2e44d56554c309483fe50993078d994779cac44f599d7bb4b310a535d0d620bc6422892f10b4c72610334ff0b709e30e8f7649f15699011e94d719da2a901dd40b76b0e6e4e04e9805de1275e036dffa16c0818fc5d89ddaa015348f1bacc45c550fae0dc66a0f82e3068280ad3f75e2aebcb21f1902818100ccfc4f0be49917ffc4f9a660a3252413dadae0527c5615e6df1e5030cfc91991685459649e25e2db970c64caa690b147fa7e542798e0522afbe03596e9193af8ea25c1e401dcd24c582e880a21544daf16b2c6abe25566835b20456017fc2602997aabdedf9f1610a1f60db73da0e7caebd7919ec2b09606d5d6d7f45d18db0d02818100c85ba9c7750ad35d08fe7e565272ec7a089cc1554ec5f3b42e403f33784215f220a3b4e8e475129f3aad23d0e6ce56feb4cbd141bc4a06968af9f980ed5b78c57c6282cb91df2d8cbfc0538de5e12afd1e7fdb4a9c2b9649ba32ddcfed3795700229db9769bd1a6d4e587d3c900ce8f6050952fc620fbb5241a656c93f25cb5b0281805ac97cb105c4106f056c9495c46c14b87e7be6526223367c1461b69e87c8c77c313afa84a7ce9bd529e72154e7c4b9dfe93fbe41f36196c2d6df8c9c940ccaa3a800a5093911f64a3ddc0e007e9679f98c120e0fdea4784cc1355fc4999ae1b2d10b15c8163ebd650c768fc892910b5842702d5ca559d4789e891308759b269902818031f05ef5ff1f4ea57ecb6813fe02f51c49af40a511b857510ec226be9e77e25e72723b725d172d281108fcc761f006510021592c08516f28f0c4f3c285e6e9c857837a54612c7e7ef980679313bc36e9d6434a1663ac9d8e0ce206d57fabfe0c680da4d52d9edbca68dfb77f73ec33d8b652a7a38e919b401a6aea70c8d393c70281810097379ff587be5d37267d516f350f68c2180d836e24428fb6da49bdfa3a170a65977fd77c457105a3d9709051cfadbb9944506824a030f31475d4e344137cd69c910e4fa71156a0d01e50766589e6a12f78d86058ffe7b1628a0adb099421669b09533463e6b6ebab5457f6bf59b6f085fb81a91c28dee21d613bb1fad3b786f6";
//		PKCS8EncodedKeySpec privKeySpec1 = new PKCS8EncodedKeySpec(StringUtil.hexDecode(pristr));
		PKCS8EncodedKeySpec privKeySpec1 = new PKCS8EncodedKeySpec(encoded);
		KeyFactory keyFact2 = KeyFactory.getInstance("RSA");
		return keyFact2.generatePrivate(privKeySpec1);
	}
	
	public static PrivateKey loadPrivateKey(String type, String filepath) throws Exception {
		// byte[] encoded = loadObject("RSA PRIVATE KEY", filepath);			// PKCS#1
		byte[] encoded = loadObject(type, filepath);			// PKCS#8
//		String pristr = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100a06e8363a9da248d179ba43bbabf4d73ef95718c0f5c67fabad6bf3b11b3ea1158e103b2f227afffa00ec8a5c7593e0d99e274b8671eec44ed066def2c37b256bc7b1e2fa7fae685d17e13c8bd810770ed6b8567395215b492cd1f2541d85dd098adab1cf048f4326c380cd4b06d5ab4a7c01834da597974f56cdca68bb56276091fc14a5f8d649ce78849de3995f136c07d289fec850cdb41c45944b131bd7a6c347b1c60612dc44027a9c910b171d9559f492e9d3cb14becedb5b448fed6b78b41de290e535a718f4f0c7f817eff8cab032c6284db3d64ce3e978e479d6289784294c20daec5eef271b9124569e6744857fcfe8968843b83607764a96a2c9f020301000102820100322579123cf43fba8e678af55491195fa4c2bca43fe4ed6774e14d12e49cad0c5110bc7c41aee01771eb4d126c765bac1aaeab373c9c70d3b696ece3f6994e38485fdf769bf613fa3e1a3f8ade99273f4826f4a2e84add17fd4efa6e45dfa0ab641ddcbf85e7f7d48ef91221a527f95340a00db0ef934a20a1da2e3a2caf3ca013d49db77e7494fed13eba2e44d56554c309483fe50993078d994779cac44f599d7bb4b310a535d0d620bc6422892f10b4c72610334ff0b709e30e8f7649f15699011e94d719da2a901dd40b76b0e6e4e04e9805de1275e036dffa16c0818fc5d89ddaa015348f1bacc45c550fae0dc66a0f82e3068280ad3f75e2aebcb21f1902818100ccfc4f0be49917ffc4f9a660a3252413dadae0527c5615e6df1e5030cfc91991685459649e25e2db970c64caa690b147fa7e542798e0522afbe03596e9193af8ea25c1e401dcd24c582e880a21544daf16b2c6abe25566835b20456017fc2602997aabdedf9f1610a1f60db73da0e7caebd7919ec2b09606d5d6d7f45d18db0d02818100c85ba9c7750ad35d08fe7e565272ec7a089cc1554ec5f3b42e403f33784215f220a3b4e8e475129f3aad23d0e6ce56feb4cbd141bc4a06968af9f980ed5b78c57c6282cb91df2d8cbfc0538de5e12afd1e7fdb4a9c2b9649ba32ddcfed3795700229db9769bd1a6d4e587d3c900ce8f6050952fc620fbb5241a656c93f25cb5b0281805ac97cb105c4106f056c9495c46c14b87e7be6526223367c1461b69e87c8c77c313afa84a7ce9bd529e72154e7c4b9dfe93fbe41f36196c2d6df8c9c940ccaa3a800a5093911f64a3ddc0e007e9679f98c120e0fdea4784cc1355fc4999ae1b2d10b15c8163ebd650c768fc892910b5842702d5ca559d4789e891308759b269902818031f05ef5ff1f4ea57ecb6813fe02f51c49af40a511b857510ec226be9e77e25e72723b725d172d281108fcc761f006510021592c08516f28f0c4f3c285e6e9c857837a54612c7e7ef980679313bc36e9d6434a1663ac9d8e0ce206d57fabfe0c680da4d52d9edbca68dfb77f73ec33d8b652a7a38e919b401a6aea70c8d393c70281810097379ff587be5d37267d516f350f68c2180d836e24428fb6da49bdfa3a170a65977fd77c457105a3d9709051cfadbb9944506824a030f31475d4e344137cd69c910e4fa71156a0d01e50766589e6a12f78d86058ffe7b1628a0adb099421669b09533463e6b6ebab5457f6bf59b6f085fb81a91c28dee21d613bb1fad3b786f6";
//		PKCS8EncodedKeySpec privKeySpec1 = new PKCS8EncodedKeySpec(StringUtil.hexDecode(pristr));
		PKCS8EncodedKeySpec privKeySpec1 = new PKCS8EncodedKeySpec(encoded);
		KeyFactory keyFact2 = KeyFactory.getInstance("RSA");
		return keyFact2.generatePrivate(privKeySpec1);
	}
	
	public static PrivateKey parsePrivateKey(String contents) throws Exception {
		return parsePrivateKey("PRIVATE KEY", contents);
	}
	
	public static PrivateKey parsePrivateKey(String type, String contents) throws Exception {
		byte[] encoded = parseObject(type, contents);
		PKCS8EncodedKeySpec privKeySpec1 = new PKCS8EncodedKeySpec(encoded);
		KeyFactory keyFact2 = KeyFactory.getInstance("RSA");
		return keyFact2.generatePrivate(privKeySpec1);
	}
/*
	@SuppressWarnings("resource")
	public static String writePrivateKey(PrivateKey key) throws Exception {
		String type = null;
		ByteArrayInputStream    byteIn = new ByteArrayInputStream(key.getEncoded());
		ASN1InputStream         ansiIn = new ASN1InputStream(byteIn);
		PrivateKeyInfo          info = new PrivateKeyInfo((ASN1Sequence)ansiIn.readObject());
		ByteArrayOutputStream   byteOut = new ByteArrayOutputStream();
		ASN1OutputStream        ansiOut = new ASN1OutputStream(byteOut);
		
		if (key instanceof RSAPrivateKey) {
			type = "RSA PRIVATE KEY";
			ansiOut.writeObject(info.getPrivateKey());
		} else if (key instanceof DSAPrivateKey) {
			type = "DSA PRIVATE KEY";
			
			DSAParameter        p = DSAParameter.getInstance(info.getAlgorithmId().getParameters());
			ASN1EncodableVector v = new ASN1EncodableVector();
			
			v.add(new DERInteger(0));
			v.add(new DERInteger(p.getP()));
			v.add(new DERInteger(p.getQ()));
			v.add(new DERInteger(p.getG()));
			
			BigInteger x = ((DSAPrivateKey)key).getX();
			BigInteger y = p.getG().modPow(x, p.getP());
			
			v.add(new DERInteger(y));
			v.add(new DERInteger(x));
			
			ansiOut.writeObject(new DERSequence(v));
		}
		
		return writeObject(type, byteOut.toByteArray());
	}
*/


	/*
	public static byte[] makeSalt(byte[] br) {
		int len = br.length;
		byte[] brNew = new byte[len];
		for (int i = 0; i < br.length; i++) {

			brNew[i] = br[Math.abs(br[i] % len)];
		}
		return brNew;
	}*/
	public static byte[] makeSalt(byte[] br) {
		int len = br.length;
		byte[] brNew = new byte[len];
		for (int i = 0; i < br.length; i++) {
			int brint = br[i] & 0xff;
			brNew[i] = br[Math.abs((byte)(brint % len))];
//			System.out.println("MAKE SALT : Index ["+i+"], Length ["+len+"]\n" +
//					"\tbr[i] ["+(brint)+"]\n" +
//					"\tbr[i]%len ["+ (brint % len)+"]\n" +
//					"\tMath.abs(br[i]%len) ["+ (Math.abs(brint % len))+"]\n" +
//					"\tbr[Math.abs(br[i] % len)] ["+ (br[Math.abs(brint % len)])+"]["+ SecuLogUtil.hexEncode(brNew)+"]");
		}
		return brNew;
	}
	
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException{
		return generateKeyPair(2048);
	}
	public static KeyPair generateKeyPair(int keysize) throws NoSuchAlgorithmException{
		KeyPair keyPair = null;
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		keyPair = kpg.genKeyPair();
//		Key clsPublicKey = keyPair.getPublic();
//		Key clsPrivateKey = keyPair.getPrivate();
		return keyPair;
	}


//	public static PublicKey parsePublicKey(String pubKey) {
//		PublicKey publicKey = null;
//		try{
//			KeySpec keySpec = new X509EncodedKeySpec(pubKey.getBytes());
//			KeyFactory kf = KeyFactory.getInstance("RSA");
//			publicKey = kf.generatePublic(keySpec);
//		}catch(Exception e){
//			e.printStackTrace();
//		}
//		return publicKey;
//	}

	private static String writeObject(String type, byte[] bytes){
		StringWriter sw = new StringWriter();
		BufferedWriter bw = null;
		try{
			char[]  buf = new char[64];
			Encoder encoder = Base64.getEncoder();
			bytes = encoder.encode(bytes);
//			bytes = StringUtil.b64Encode(bytes);
			bw = new BufferedWriter(sw);
			bw.write("-----BEGIN " + type + "-----");
			bw.newLine();
			for (int i = 0; i < bytes.length; i += buf.length) {
				int index = 0;
				while (index != buf.length) {
					if ((i + index) >= bytes.length) {
						break;
					}
					buf[index] = (char)bytes[i + index];
					index++;
				}
				bw.write(buf, 0, index);
				bw.newLine();
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
	

	private static byte[] loadObject(String type, String filepath) throws IOException {
		BufferedReader reader = new BufferedReader(new FileReader(filepath));
		String line = null;
		StringBuilder builder = new StringBuilder();
		String ls = System.getProperty("line.separator");

		try {
			while ((line = reader.readLine()) != null) {
				builder.append(line.trim());
//				builder.append(ls);
			}

			return parseObject(type, builder.toString());
		} finally {
			try { reader.close(); } catch(Exception e) { }
		}
	}
	
	private static byte[] parseObject(String type, String contents) throws IOException {
//		System.out.println("Object : " + contents);
		String data = contents
				.replace("-----BEGIN " + type + "-----", "")
				.replace("-----END " + type + "-----", "")
				.replace("\r", "")
				.replace("\n", "");
		
		Decoder decoder = Base64.getDecoder();
		byte[] decodedBytes = decoder.decode(data.getBytes());

		return decodedBytes;
//		return StringUtil.b64Decode(data.trim());
	}
	
	public static String writeLicense(FileInputStream stream) throws Exception {
		BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
		String line = null;
		StringBuilder builder = new StringBuilder();
		String ls = System.getProperty("line.separator");

		try {
			while ((line = reader.readLine()) != null) {
				builder.append(line.trim());
				builder.append(ls);
			}
			return writeObject("LICENSE", builder.toString().getBytes());
		} finally {
			try { reader.close(); } catch(Exception e) { e.printStackTrace();}
		}
	}
	
	public static String writeLicense(String lic) throws Exception {
		return writeObject("LICENSE", lic.getBytes());
	}
	
	public static ByteArrayInputStream loadLicense(String lic) throws Exception {
		String contents = lic.replace("-----BEGIN LICENSE-----", "").replace("-----END LICENSE-----", "").replace("\r\n", "");

		Decoder decoder = Base64.getDecoder();
		byte[] decodedBytes = decoder.decode(contents.getBytes());

//		ByteArrayInputStream bis = new ByteArrayInputStream(StringUtil.b64Decode(contents.trim()));
		ByteArrayInputStream bis = new ByteArrayInputStream(decodedBytes);
		
		return bis;
	}
}
