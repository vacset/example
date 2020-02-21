package example;

import com.sun.org.apache.xml.internal.security.encryption.EncryptedData;
import com.sun.org.apache.xml.internal.security.encryption.EncryptedKey;
import com.sun.org.apache.xml.internal.security.encryption.XMLCipher;
import com.sun.org.apache.xml.internal.security.keys.KeyInfo;

import org.apache.log4j.BasicConfigurator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.spec.KeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class EncryptSymmetric {

	static SecretKey generateAndStoreKEK(String filename) throws Exception {
		String algo = "DESede";
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
		SecretKey k = keyGenerator.generateKey();
		byte [] keyBytes = k.getEncoded();
		File kekFile = new File(filename);
		FileOutputStream f = new FileOutputStream(kekFile);
		f.write(keyBytes);
		f.close();
		System.out.println("KEK file" + kekFile.toURI().toURL().toString());
		return k;
	}

	static SecretKey generateDataEncryptionKey() throws Exception {
		String algo = "AES";
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
		keyGenerator.init(128);// key-length
		SecretKey k = keyGenerator.generateKey();
		return k;
	}

	static SecretKey loadKEK(String filename) throws Exception {
		String algo = "DESede";
		File kekFile = new File(filename);
		System.out.println("KEK file" + kekFile.toURI().toURL().toString());
		FileInputStream fs = new FileInputStream(kekFile);
		byte [] kekBytes = new byte[(int)kekFile.length()];
		fs.read(kekBytes);
		fs.close();

		KeySpec keySpec = new DESedeKeySpec(kekBytes);
		SecretKeyFactory fac = SecretKeyFactory.getInstance(algo);
		SecretKey k = fac.generateSecret(keySpec);
		return k;
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
		File encryptedXmlFile = new File("D:\\vacset\\DEV\\2018\\encrypted_symmetric_result.xml");

		Document doc = createDocument(plainXmlFile);
		Element rootElem = doc.getDocumentElement();
		Key symmetricKey = generateDataEncryptionKey();
		Key kek = generateAndStoreKEK("D:\\vacset\\DEV\\2018\\symmetricKeyKEK");

		XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES_KeyWrap);
		keyCipher.init(XMLCipher.WRAP_MODE, kek);
		EncryptedKey encryptedKey = keyCipher.encryptKey(doc, symmetricKey);
		KeyInfo ki = new KeyInfo(doc);
		ki.add(encryptedKey);

		XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
		EncryptedData encryptedData = xmlCipher.getEncryptedData();
		encryptedData.setKeyInfo(ki);

		xmlCipher.doFinal(doc, rootElem, true);

		FileOutputStream os = new FileOutputStream(encryptedXmlFile);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(doc), new StreamResult(os));
		os.close();

	}

}
