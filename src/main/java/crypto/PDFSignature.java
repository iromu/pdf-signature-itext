package crypto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

public class PDFSignature {
	private static final int srcBufSize = 10 * 1024;

	private static byte[] src = new byte[srcBufSize];
	static {
		src[srcBufSize - 1] = 'x';
	}
	static Logger log = Logger.getLogger(PDFSignature.class);
	private static byte[] digest;
	private List<byte[]> digests = new ArrayList<byte[]>();

	private List<byte[]> signatures = new ArrayList<byte[]>();

	public void process(String pdf) {
		digests = new ArrayList<byte[]>();
		log.info("pdf name: " + pdf);
		signatures = new ArrayList<byte[]>();
		try {
			KeyStore kall = PdfPKCS7.loadCacertsKeyStore();

			// Cargar pdf
			PdfReader reader = new PdfReader(pdf);
			AcroFields fields = reader.getAcroFields();

			String document = pdf.replaceAll("/", "-");

			ArrayList<String> signatures = fields.getSignatureNames();
			log.info("Firmas: " + signatures.size());
			for (String signature : signatures) {

				log.info("Signature name: " + signature);
				log.info("Signature covers whole document: "
						+ fields.signatureCoversWholeDocument(signature));
				log.info("Document revision: " + fields.getRevision(signature)
						+ " of " + fields.getTotalRevisions());
				// Start revision extraction
				/*
				 * 
				 * FileOutputStream out = new FileOutputStream(document +
				 * "-revision_" + fields.getRevision(signature) + ".pdf"); byte
				 * bb[] = new byte[8192]; InputStream ip =
				 * fields.extractRevision(signature); int n = 0; while ((n =
				 * ip.read(bb)) > 0) out.write(bb, 0, n); out.close();
				 * ip.close();
				 */
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				byte bb[] = new byte[8192];
				InputStream ip = fields.extractRevision(signature);
				int n = 0;
				while ((n = ip.read(bb)) > 0)
					out.write(bb, 0, n);
				out.close();
				ip.close();
				MessageDigest md = MessageDigest.getInstance("SHA1");
				byte[] resum = md.digest(out.toByteArray());
				digests.add(resum);

				// End revision extraction
				try {
					PdfPKCS7 pk = fields.verifySignature(signature);
					Calendar cal = pk.getSignDate();
					Certificate pkc[] = pk.getCertificates();
					log.info("Subject: "
							+ PdfPKCS7.getSubjectFields(pk
									.getSigningCertificate()));
					log.info("Document modified: " + !pk.verify());

					Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall,
							null, cal);
					if (fails == null)
						log.info("Certificates verified against the KeyStore");
					else
						log.info("Certificate failed: " + fails[1]);

					X509Certificate certificate = pk.getSigningCertificate();
					//
					 FileUtils.writeByteArrayToFile(new File(document + "-"
					 + signature + "_.crt"), certificate.getEncoded());

					Class<?> c = PdfPKCS7.class;

					Field f = c.getDeclaredField("digest");
					f.setAccessible(true);

					digest = byte[].class.cast(f.get(pk));
//
//					FileUtils.writeByteArrayToFile(
//							new File(document + "_.hash"), digest);

					f = c.getDeclaredField("sig");
					f.setAccessible(true);
				} catch (Exception e) {
					log.error(e, e);
				}

				// Signature sig = Signature.class.cast(f.get(pk));
				// c = Signature.class;
				//			
				// pkcs7 = byte[].class.cast(f.get(sig));
				// //

				PdfDictionary dictionary = fields
						.getSignatureDictionary(signature);

				PdfName key = new PdfName("Contents");
				byte[] encodedPKCS7 = dictionary.get(key).getBytes();

				this.signatures.add(encodedPKCS7);
			}
		} catch (Exception e) {
			log.error(e, e);
		}

	}

	public List<byte[]> getDigests() {
		return digests;
	}

	public void setDigests(List<byte[]> digests) {
		this.digests = digests;
	}

	public List<byte[]> getSignatures() {
		return signatures;
	}

	public void setSignatures(List<byte[]> signatures) {
		this.signatures = signatures;
	}
}
