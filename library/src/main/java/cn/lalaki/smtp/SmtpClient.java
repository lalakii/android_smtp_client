package cn.lalaki.smtp;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;
import java.util.UUID;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/***
 * @author lalaki - i@lalaki.cn <a href=
 *         "https://github.com/lalakii/android_smtp_client">android_smtp_client</a>
 * @version 3.0.2
 */
@SuppressWarnings("CharsetObjectCanBeUsed")
public abstract class SmtpClient {
    private static final Charset charset = Charset.forName("UTF-8");
    private static final String hostname = "localhost.localdomain";
    private static final int timeout = 30000;
    private SmtpClient.Builder mBuilder;

    public enum TlsMode {
        STARTTLS, IMPLICIT_TLS
    }

    public enum ContentType {
        TEXT_PLAIN, TEXT_HTML
    }

    public enum Priority {
        Highest, High, Normal, Low, Lowest
    }

    public interface IMailSentListener {
        void onSuccess();

        void onError(Exception e);

        void onLog(String log);
    }

    public abstract void sendMail(EmailMessage message, IMailSentListener listener);

    protected static void sendMail(SSLSocketFactory factory, InetSocketAddress address, String host, TlsMode mode,
                                   String username, String password, boolean insecure, String to, String subject, String body,
                                   ContentType contentType, Priority priority, List<File> attachments, IMailSentListener listener) {
        try {
            String base64Username = base64EncodeToString(username);
            String type = "text/plain";
            if (contentType == ContentType.TEXT_HTML) {
                type = "text/html";
            }
            if (mode == TlsMode.STARTTLS) {
                sendMailWithSTARTTLS(factory, address, host, mode, username, base64Username, password, insecure, to,
                        subject, body, type, priority, attachments, listener);
            } else if (mode == TlsMode.IMPLICIT_TLS) {
                sendMailWithTLS(factory, address, mode, username, base64Username, password, insecure, to, subject, body,
                        type, priority, attachments, listener);
            }
            if (listener != null) {
                listener.onSuccess();
            }
        } catch (Exception e) {
            if (listener != null) {
                listener.onError(e);
            }
        }
    }

    private static void sendMailWithTLS(SSLSocketFactory factory, InetSocketAddress address, TlsMode mode,
                                        String username, String baseUserName, String password, boolean insecure, String to, String subject,
                                        String body, String contentType, Priority priority, List<File> attachments, IMailSentListener listener)
            throws Exception {
        SSLSocket tlsSocket = (SSLSocket) factory.createSocket();
        tlsSocket.setSoTimeout(timeout);
        tlsSocket.connect(address, timeout);
        upgradeToTls(mode, username, baseUserName, password, to, subject, body, contentType, priority, insecure,
                attachments, listener, tlsSocket);
    }

    private static void sendMailWithSTARTTLS(SSLSocketFactory factory, InetSocketAddress address, String host,
                                             TlsMode mode, String username, String baseUserName, String password, boolean insecure, String to,
                                             String subject, String body, String contentType, Priority priority, List<File> attachments,
                                             IMailSentListener listener) throws Exception {
        try (Socket plainSocket = new Socket()) {
            plainSocket.setSoTimeout(timeout);
            plainSocket.connect(address, timeout);
            Scanner reader = new Scanner(plainSocket.getInputStream(), charset.name());
            expect(reader, "220", listener);
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(plainSocket.getOutputStream(), charset), false);
            println(writer, "EHLO ", false, listener);
            println(writer, hostname, listener);
            skip(reader, listener);
            println(writer, "STARTTLS", listener);
            expect(reader, "220", listener);
            upgradeToTls(mode, username, baseUserName, password, to, subject, body, contentType, priority, insecure,
                    attachments, listener,
                    (SSLSocket) factory.createSocket(plainSocket, host, address.getPort(), true));
        }
    }

    private static void upgradeToTls(TlsMode mode, String username, String baseUserName, String password, String to,
                                     String subject, String body, String contentType, Priority priority, boolean insecure,
                                     List<File> attachments, IMailSentListener listener, SSLSocket tlsSocket) throws Exception {
        try (tlsSocket) {
            if (!insecure) {
                SSLParameters sslParams = tlsSocket.getSSLParameters();
                try {
                    sslParams.getClass().getMethod("setEndpointIdentificationAlgorithm", String.class).invoke(sslParams,
                            "HTTPS");
                    tlsSocket.setSSLParameters(sslParams);
                } catch (Exception ignored) {
                    throw new UnsupportedOperationException(
                            "The method setEndpointIdentificationAlgorithm is not supported!\r\nAlternative: set the insecure parameter to true.");
                }
            }
            tlsSocket.startHandshake();
            Scanner reader = new Scanner(tlsSocket.getInputStream(), charset.name());
            if (mode == TlsMode.IMPLICIT_TLS) {
                expect(reader, "220", listener);
            }
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(tlsSocket.getOutputStream(), charset), false);
            StringBuilder packet = new StringBuilder();
            packet.append("EHLO ").append(hostname);
            println(writer, packet, listener);
            skip(reader, listener);
            println(writer, "AUTH LOGIN", listener);
            expect(reader, "334", listener);
            println(writer, baseUserName, listener);
            expect(reader, "334", listener);
            println(writer, base64EncodeToString(password), listener);
            expect(reader, "235", listener);
            packet.append("MAIL FROM:<").append(username).append(">");
            println(writer, packet, listener);
            expect(reader, "250", listener);
            packet.append("RCPT TO:<").append(to).append(">");
            println(writer, packet, listener);
            expect(reader, "250", listener);
            println(writer, "DATA", listener);
            expect(reader, "354", listener);
            packet.append(getMessageId(username)).append(getXMailer()).append(getPriority(priority)).append("Date: ")
                    .append(getMailDate()).append("\r\nFrom: ").append(username).append("\r\nTo: ").append(to)
                    .append("\r\nSubject: ");
            appendUtf8NonASCII(packet, subject).append("\r\nMIME-Version: 1.0\r\nContent-Type: ");
            if (attachments == null) {
                packet.append(contentType).append("; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
                        .append(base64EncodeToString(body));
            } else {
                String boundary = String.format("----=_Part_%s", UUID.randomUUID());
                packet.append("multipart/mixed; boundary=\"").append(boundary);
                boundary = String.format("--%s", boundary);
                packet.append("\"\r\n\r\n").append(boundary).append("\r\nContent-Type: ").append(contentType)
                        .append("; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
                        .append(base64EncodeToString(body));
                for (File file : attachments) {
                    packet.append("\r\n\r\n").append(boundary).append("\r\nContent-Type: ")
                            .append(URLConnection.guessContentTypeFromName(file.getName()))
                            .append("\r\nContent-Disposition: attachment; filename=\"");
                    appendUtf8NonASCII(packet, file.getName()).append("\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
                            .append(fileToBase64String(file));
                }
                packet.append("\r\n\r\n").append(boundary).append("--");
            }
            packet.append("\r\n.");
            println(writer, packet, listener);
            expect(reader, "250", listener);
            println(writer, "QUIT", listener);
            expect(reader, "221", listener);
        }
    }

    private static StringBuilder appendUtf8NonASCII(StringBuilder packet, String text) throws Exception {
        return packet.append("=?utf-8?B?").append(base64EncodeToString(text)).append("?=");
    }

    private static String fileToBase64String(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead;
            byte[] buffer = new byte[4096];
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            return base64EncodeToString(os.toByteArray());
        }
    }

    private static String getMailDate() {
        return new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());
    }

    private static String getXMailer() {
        String version = null;
        try {
            Class<?> versionClazz = Class.forName("android.os.Build$VERSION");
            Object versionObj = versionClazz.getField("RELEASE").get(null);
            if (versionObj instanceof String) {
                version = String.format("Android %s", versionObj);
            }
        } catch (Exception ignored) {
            version = String.format("Java/%s", System.getProperty("java.version"));
        }
        return String.format("X-Mailer: Android SMTP Client/2.3 (%s; lalaki_dev)\r\n", version);
    }

    private static String getPriority(Priority priority) {
        int p;
        if (priority == Priority.Highest) {
            p = 1;
        } else if (priority == Priority.High) {
            p = 2;
        } else if (priority == Priority.Low) {
            p = 4;
        } else if (priority == Priority.Lowest) {
            p = 5;
        } else {
            p = 3;
        }
        return String.format("X-Priority: %s\r\n", p);
    }

    private static String getMessageId(String username) {
        int index = username.indexOf('@');
        String domain = hostname;
        if (index != -1) {
            domain = username.substring(index + 1);
        }
        return String.format("Message-ID: <%s@%s>\r\n", UUID.randomUUID(), domain);
    }

    private static String base64EncodeToString(String text) throws Exception {
        return base64EncodeToString(text.getBytes(charset));
    }

    private static String base64EncodeToString(byte[] data) throws Exception {
        Object base64String = null;
        try {
            Class<?> androidBase64Clazz = Class.forName("android.util.Base64");
            base64String = androidBase64Clazz.getMethod("encodeToString", byte[].class, int.class).invoke(null, data,
                    androidBase64Clazz.getField("CRLF").getInt(null));
        } catch (Exception e) {
            Object javaMimeEncoderObj = Class.forName("java.util.Base64").getMethod("getMimeEncoder").invoke(null);
            if (javaMimeEncoderObj != null) {
                base64String = javaMimeEncoderObj.getClass().getMethod("encodeToString", byte[].class)
                        .invoke(javaMimeEncoderObj, (Object) data);
            }
        }
        if (base64String instanceof String) {
            return ((String) base64String).trim().trim();
        }
        throw new IOException("Base64 encoding failed!");
    }

    private static void println(PrintWriter writer, StringBuilder packet, IMailSentListener listener) {
        println(writer, packet.toString(), true, listener);
        packet.setLength(0);
    }

    private static void println(PrintWriter writer, String text, IMailSentListener listener) {
        println(writer, text, true, listener);
    }

    private static void println(PrintWriter writer, String text, boolean newLine, IMailSentListener listener) {
        writer.print(text);
        if (newLine) {
            writer.print("\r\n");
        }
        writer.flush();
        printLog("CLIENT", text, listener);
    }

    private static void printLog(String prefix, String text, IMailSentListener listener) {
        if (listener != null) {
            listener.onLog(String.format("%s: %s", prefix, text));
        }
    }

    private static void expect(Scanner reader, String prefix, IMailSentListener listener) throws IOException {
        if (!reader.hasNextLine()) {
            throw new IOException("Connection unexpectedly closed!");
        }
        String line = reader.nextLine();
        printLog("SERVER", line, listener);
        if (!line.contains(prefix)) {
            throw new IOException(String.format("Not the expected return value! %s != %s", prefix, line));
        }
    }

    private static void skip(Scanner reader, IMailSentListener listener) {
        while (reader.hasNextLine()) {
            String line = reader.nextLine();
            printLog("SERVER", line, listener);
            if (!line.contains("-")) {
                break;
            }
        }
    }

    private SmtpClient(Builder builder) {
        setBuilder(builder);
    }

    protected SmtpClient.Builder getBuilder() {
        return mBuilder;
    }

    private void setBuilder(SmtpClient.Builder mBuilder) {
        this.mBuilder = mBuilder;
    }

    private static class DefaultSmtpClient extends SmtpClient {
        public void sendMail(EmailMessage message, IMailSentListener listener) {
            SmtpClient.Builder builder = getBuilder();
            if (builder != null) {
                sendMail(builder.getFactory(), builder.getAddress(), builder.getHost(), builder.getMode(),
                        builder.getUsername(), builder.getPassword(), builder.getInsecure(), message.getTo(),
                        message.getSubject(), message.getBody(), message.getBodyContentType(), message.getPriority(),
                        message.getAttachments(), listener);
            }
        }

        public DefaultSmtpClient(SmtpClient.Builder builder) {
            super(builder);
        }
    }

    public static class SmtpConfig {
        private SmtpClient.Builder mBuilder;

        private SmtpConfig(SmtpClient.Builder builder) {
            setBuilder(builder);
        }

        public SmtpClient build() {
            return new DefaultSmtpClient(getBuilder());
        }

        private SmtpClient.Builder getBuilder() {
            return mBuilder;
        }

        private void setBuilder(SmtpClient.Builder mBuilder) {
            this.mBuilder = mBuilder;
        }
    }

    public static class EmailMessage {
        private String mTo;
        private String mSubject;
        private String mBody;
        private ContentType mBodyContentType;
        private List<File> mAttachments;
        private Priority mPriority;

        public EmailMessage(String to, String subject, String body, ContentType bodyContentType, List<File> attachments,
                            Priority priority) {
            setTo(to);
            setSubject(subject);
            setBody(body);
            setBodyContentType(bodyContentType);
            setAttachments(attachments);
            setPriority(priority);
        }

        private String getTo() {
            return mTo;
        }

        private void setTo(String mTo) {
            this.mTo = mTo;
        }

        private String getSubject() {
            return mSubject;
        }

        private void setSubject(String mSubject) {
            this.mSubject = mSubject;
        }

        private String getBody() {
            return mBody;
        }

        private void setBody(String mBody) {
            this.mBody = mBody;
        }

        private ContentType getBodyContentType() {
            return mBodyContentType;
        }

        private void setBodyContentType(ContentType mBodyContentType) {
            this.mBodyContentType = mBodyContentType;
        }

        private List<File> getAttachments() {
            return mAttachments;
        }

        private void setAttachments(List<File> mAttachments) {
            this.mAttachments = mAttachments;
        }

        private Priority getPriority() {
            return mPriority;
        }

        private void setPriority(Priority mPriority) {
            this.mPriority = mPriority;
        }
    }

    public static class Builder {
        private String mHost;
        private TlsMode mMode;
        private String mUsername;
        private String mPassword;
        private SSLSocketFactory mFactory;
        private InetSocketAddress mAddress;
        private boolean mInsecure;

        public SmtpConfig config(String host, int port, TlsMode mode, boolean insecure, String username,
                                 String password) {
            this.setHost(host);
            this.setMode(mode);
            this.setInsecure(insecure);
            this.setUsername(username);
            this.setPassword(password);
            this.setFactory((SSLSocketFactory) SSLSocketFactory.getDefault());
            try {
                this.setAddress(new InetSocketAddress(host, port));
            } catch (Exception ignored) {
            }
            return new SmtpConfig(this);
        }

        public boolean getInsecure() {
            return mInsecure;
        }

        public void setInsecure(boolean mInsecure) {
            this.mInsecure = mInsecure;
        }

        public InetSocketAddress getAddress() {
            return mAddress;
        }

        public void setAddress(InetSocketAddress mAddress) {
            this.mAddress = mAddress;
        }

        private void setFactory(SSLSocketFactory mFactory) {
            this.mFactory = mFactory;
        }

        private SSLSocketFactory getFactory() {
            return mFactory;
        }

        private String getPassword() {
            return mPassword;
        }

        private void setPassword(String mPassword) {
            this.mPassword = mPassword;
        }

        private String getUsername() {
            return mUsername;
        }

        private void setUsername(String mUsername) {
            this.mUsername = mUsername;
        }

        private TlsMode getMode() {
            return mMode;
        }

        private void setMode(TlsMode mMode) {
            this.mMode = mMode;
        }

        private String getHost() {
            return mHost;
        }

        private void setHost(String mHost) {
            this.mHost = mHost;
        }
    }
}