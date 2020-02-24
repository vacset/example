package example;

import com.sun.org.apache.xml.internal.security.encryption.XMLCipher;

import org.apache.log4j.BasicConfigurator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Enumeration;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class DecryptAsymmetric {

	/**
	 * Read the given stream of PFX file and return a KeyPair of the private key.
	 * Caller should handle stream closing. At least 1 private key should be
	 * present, and this function assume that there should be a passphrase
	 * protecting the private key.
	 *
	 * @param pfxStream
	 * @return
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnrecoverableEntryException
	 */
	public static KeyPair readPfxKeyPair(InputStream pfxStream, char[] passphrase) throws Exception {
		KeyPair kp = null;

		KeyStore keystore = KeyStore.getInstance("pkcs12");

		keystore.load(pfxStream, passphrase);
		for (Enumeration<String> aliasItr = keystore.aliases(); aliasItr.hasMoreElements();) {
			String alias = aliasItr.nextElement();
			java.security.cert.Certificate c = keystore.getCertificate(alias);
			KeyStore.PrivateKeyEntry e = (PrivateKeyEntry) keystore.getEntry(alias,
					new KeyStore.PasswordProtection(passphrase));

			if (null == e) { // private key not found, skip
				continue;
			}

			// found the key! exit loop
			kp = new KeyPair(c.getPublicKey(), e.getPrivateKey());
			break;
		}

		if (null == kp) {
			throw new IllegalArgumentException("Could not read key from the given PFX");
		}

		return kp;
	}

	static Document createDocument(File f) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder builder;
		Document doc = null;
		FileInputStream fs = new FileInputStream(f);
		builder = dbf.newDocumentBuilder();
		doc = builder.parse(fs);
		fs.close();
		return doc;
	}

	public static void main(String[] args) throws Exception {
		BasicConfigurator.configure();
		com.sun.org.apache.xml.internal.security.Init.init();
		File plainXmlFile = new File("D:\\vacset\\DEV\\2018\\expected_decryptresult.xml");
		File encryptedXmlFile = new File("D:\\vacset\\DEV\\2018\\encrypted_asymmetric_result.xml");
		File decryptedXmlFile = new File("D:\\vacset\\DEV\\2018\\decrypted_asymmetric_result.xml");
		File pfxFile = new File("D:\\vacset\\DEV\\2018\\Original\\MIZUHO BANK_MASAKI.p12");
		char [] pass = "0687".toCharArray();

		Document doc = createDocument(encryptedXmlFile);
		Element rootElem = doc.getDocumentElement();
		InputStream is = new FileInputStream(pfxFile);
		KeyPair keyPair = readPfxKeyPair(is, pass);
		is.close();

		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		xmlCipher.setKEK(keyPair.getPrivate());
		xmlCipher.doFinal(doc, rootElem, true);

		FileOutputStream os = new FileOutputStream(decryptedXmlFile);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(doc), new StreamResult(os));
		os.close();

	}

}
