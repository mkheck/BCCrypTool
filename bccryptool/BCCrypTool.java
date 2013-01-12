package bccryptool;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.*;
import javax.mail.internet.*;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;

/**
 *
 * @author mheckler
 */
public class BCCrypTool {

    public static void send(String smtpHost, int smtpPort,
            final String from, String to,
            String subject, String content, final String passwd) {

        try {

            boolean isAlias = false;

            // First, we create the plain email message (basic fields, config)
            Properties props = System.getProperties();
            props.setProperty("mail.smtp.host", smtpHost);
            props.setProperty("mail.smtp.port", "" + smtpPort);
            props.setProperty("mail.smtp.auth", "true");
            props.setProperty("mail.smtp.starttls.enable", "true");
            Session session = Session.getDefaultInstance(props,
                    new Authenticator() {
                        @Override
                        protected PasswordAuthentication getPasswordAuthentication() {
                            return new PasswordAuthentication(from,
                                    passwd);
                        }
                    });

            // Construct the message body
            MimeMessage body = new MimeMessage(session);
            body.setFrom(new InternetAddress(from));
            body.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
            body.setSubject(subject);
            body.setContent(content, "text/plain");
            body.saveChanges();

            // Add BouncyCastle content handlers to command map
            MailcapCommandMap mailcap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();

            mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
            mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
            mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
            mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
            mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

            CommandMap.setDefaultCommandMap(mailcap);

            Security.addProvider(new BouncyCastleProvider());

            KeyStore keyStore = KeyStore.getInstance("JKS");

            // Provide location of Java Keystore and password for access
            keyStore.load(new FileInputStream("D:\\ks\\test10.jks"),
                    "oracle12".toCharArray());

            // Find the first legit alias in the keystore and use it
            Enumeration<String> es = keyStore.aliases();
            String alias = "";
            while (es.hasMoreElements()) {
                alias = (String) es.nextElement();

                // Does alias refer to a private key? Assign true/false to isAlias & evaluate
                if (isAlias = keyStore.isKeyEntry(alias)) {
                    break;
                }
            }
            if (isAlias) {
                KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection("oracle12".toCharArray()));
                PrivateKey myPrivateKey = pkEntry.getPrivateKey();

                // Load certificate chain
                Certificate[] chain = keyStore.getCertificateChain(alias);

                // Create the SMIMESignedGenerator
                SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
                capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
                capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
                capabilities.addCapability(SMIMECapability.dES_CBC);
                capabilities.addCapability(SMIMECapability.aES256_CBC);

                ASN1EncodableVector attributes = new ASN1EncodableVector();
                attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
                        new IssuerAndSerialNumber(
                        new X500Name(((X509Certificate) chain[0])
                        .getIssuerDN().getName()),
                        ((X509Certificate) chain[0]).getSerialNumber())));
                attributes.add(new SMIMECapabilitiesAttribute(capabilities));

                SMIMESignedGenerator signer = new SMIMESignedGenerator();
                signer.addSigner(
                        myPrivateKey,
                        (X509Certificate) chain[0],
                        "DSA".equals(myPrivateKey.getAlgorithm()) ? SMIMESignedGenerator.DIGEST_SHA1
                        : SMIMESignedGenerator.DIGEST_MD5,
                        new AttributeTable(attributes), null);

                // Add the list of certs to the generator
                List certList = new ArrayList();
                certList.add(chain[0]);
                CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
                signer.addCertificatesAndCRLs(certs);

                // Sign the message
                MimeMultipart mm = signer.generate(body, "BC");
                MimeMessage signedMessage = new MimeMessage(session);

                // Set all original MIME headers in the signed message
                Enumeration headers = body.getAllHeaderLines();
                while (headers.hasMoreElements()) {
                    signedMessage.addHeaderLine((String) headers.nextElement());
                }

                // Set the content of the signed message
                signedMessage.setContent(mm);
                signedMessage.saveChanges();

                // Send the message
                Transport.send(signedMessage);
            }
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertStoreException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SMIMEException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableEntryException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MessagingException ex) {
            Logger.getLogger(BCCrypTool.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void printHelp() {
        System.out.println("Correct format for CrypTool is:\n\n"
                + "java CrypTool smtpHost, smtpPort, from, to, subject, content, passwd\n\n"
                + "where the parameters are as follows:\n\n"
                + "smtpHost       String variable containing the SMTP server name or address\n"
                + "smtpPort       int variable for the SMTP server's valid port, e.g. 587\n"
                + "fromAddress    String variable containing the sending email address, e.g. mark.heckler@gmail.com\n"
                + "toAddress      String variable containing the recipient's email address, e.g. mark.heckler@gmail.com\n"
                + "subject        String variable with the email's Subject Line contents\n"
                + "content        String variable containing the email message body\n"
                + "passwd         String variable with the sending email user's (mail server) password\n\n"
                + "Please try again with all parameters!");
    }

    public static void main(String[] args) throws Exception {
        // send(String smtpHost, int smtpPort, String fromAddress, String toAddress, String subject, String content, String passwd)
        if (args.length != 7) {
            printHelp();
        } else {
            try {
                int portNum = Integer.parseInt(args[1]);
                send(args[0], portNum, args[2], args[3], args[4], args[5], args[6]);
            } catch (NumberFormatException ex) {
                printHelp();
            }
        }
    }
}
