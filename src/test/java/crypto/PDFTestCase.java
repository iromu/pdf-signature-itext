package crypto;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

//import ws.xfire.psis.CadesDetachedValidation;
//import x0CoreSchema.oasisNamesTcDss1.VerifyResponseDocument;

public class PDFTestCase {
	@Test
	public void testExtract() {
		// PDFUtil.extractPKCS7("signed.pdf");
		//
		// PDFUtil.extractPKCS7("geec/doc_a.pdf");

		yu("signed.pdf");
		yu("geec/doc_a.pdf");
		// Result checkResult = null;
		// try {
		// checkResult = ResponseChecker.checkResult(validate);
		// assertEquals("urn:oasis:names:tc:dss:1.0:resultmajor:Success",
		// checkResult.getResultMajor());
		// } catch (IOException e) {
		// fail(e.getMessage());
		// }

	}

	private void yu(String pdf) {
		try {
			String document = pdf.replaceAll("/", "-");
			PDFSignature signature = new PDFSignature();
			signature.process(pdf);

			List<byte[]> hash = signature.getDigests();
			List<byte[]> signatures = signature.getSignatures();
			for (byte[] bs : hash) {
				FileUtils.writeByteArrayToFile(new File("target/" + document
						+ "_.hash"), bs);
			}
			for (byte[] bs : signatures) {
				FileUtils.writeByteArrayToFile(new File("target/" + document
						+ "_.p7b"), bs);
			}

			/*
			 * try { VerifyResponseDocument validate = CadesDetachedValidation
			 * .validate(signatures.get(0), hash.get(0));
			 * 
			 * byte[] bytes = validate.toString().getBytes();
			 * 
			 * FileUtils.writeByteArrayToFile(new File("target/" + document +
			 * "-response.xml"), bytes); } catch (Exception e) {
			 * e.printStackTrace(); }
			 */

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
