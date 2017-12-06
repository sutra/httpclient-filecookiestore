package org.oxerr.http.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import java.util.TimeZone;
import java.util.logging.Logger;

import org.apache.http.client.CookieStore;
import org.apache.http.cookie.ClientCookie;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;

/**
 * Implementation of {@link CookieStore} using file as backend store.
 */
public class FileCookieStore extends BasicCookieStore implements AutoCloseable {

	private static final long serialVersionUID = 2017101401L;

	private static final int FIELD_COUNT = 7;

	private static final String COMMENT_PREFIX = "#";
	private static final String SERIALIZED_PREFIX = "#/* ";
	private static final String SERIALIZED_SUFFIX = " */#";

	private final Logger log = Logger.getLogger(getClass().getName());
	private final Charset charset = StandardCharsets.UTF_8;
	private final File file;

	public FileCookieStore(File file) throws IOException {
		this.file = file;
		if (file.canRead()) {
			try {
				read();
			} catch (ClassNotFoundException e) {
				throw new IOException(e);
			}
		} else {
			log.fine("file " + file.toString() + " cannot be read.");
		}
	}

	@Override
	public void close() throws IOException {
		write();
	}

	private void read() throws IOException, ClassNotFoundException {
		try (
			FileInputStream fin = new FileInputStream(file);
			InputStreamReader isr = new InputStreamReader(fin, charset);
			BufferedReader br = new BufferedReader(isr);
			LineNumberReader lnr = new LineNumberReader(br);
		) {
			String line;
			while ((line = lnr.readLine()) != null) {
				if (line.startsWith(SERIALIZED_PREFIX) && line.endsWith(SERIALIZED_SUFFIX)) {
					String serialized = line.substring(SERIALIZED_PREFIX.length(),
						line.length() - SERIALIZED_SUFFIX.length());
					Cookie cookie = (Cookie) deserialize(serialized);
					log.finer("Adding cookie: " + cookie);
					addCookie(cookie);

					log.finer("Skipping next line");
					lnr.readLine();
				} else if (line.startsWith(COMMENT_PREFIX)) {
					log.finer("Skipping comment line");
				} else {
					Cookie cookie = read(line);
					log.finer("Adding cookie: " + cookie);
					addCookie(cookie);
				}
			}
		}
	}

	private Cookie read(String cookieString) {
		log.fine("cookieString: " + cookieString);

		String[] cookieStrings = cookieString.split("\t", FIELD_COUNT);

		String domain = cookieStrings[0];
		@SuppressWarnings("unused")
		boolean hostOnly = !Boolean.parseBoolean(cookieStrings[1]);
		String path = cookieStrings[2];
		boolean secure = Boolean.parseBoolean(cookieStrings[3]);
		long expiryEpochSecond = Long.parseLong(cookieStrings[4]);
		String name = cookieStrings[5];
		String value = cookieStrings[6];

		Cookie cookie;

		BasicClientCookie cc = new BasicClientCookie(name, value);

		cc.setAttribute(ClientCookie.DOMAIN_ATTR, domain);
		cc.setAttribute(ClientCookie.PATH_ATTR, path);

		cc.setDomain(domain.replaceAll("^\\.", ""));
		cc.setPath(path);
		cc.setSecure(secure);
		if (expiryEpochSecond != 0L) {
			Date expiryDate = new Date(expiryEpochSecond * 1000);
			SimpleDateFormat format = new SimpleDateFormat("EEE, dd-MMM-yyyy HH:mm:ss z");
			format.setTimeZone(TimeZone.getTimeZone("GMT"));
			String expires = format.format(expiryDate);
			cc.setAttribute(ClientCookie.EXPIRES_ATTR, expires);
			cc.setExpiryDate(expiryDate);
		}

		cookie = cc;
		return cookie;
	}

	private void write() throws IOException {
		try (
			FileOutputStream fileOutputStream = new FileOutputStream(file);
			OutputStreamWriter outputStreamWriter = new OutputStreamWriter(fileOutputStream, charset);
			BufferedWriter bw = new BufferedWriter(outputStreamWriter);
		) {
			bw.write(COMMENT_PREFIX + " domain\tnot host only\tpath\tsecure\texpiry date\tname\tvalue\n");
			for (Cookie cookie : getCookies()) {
				write(bw, cookie);
			}
		}
	}

	private void write(Writer w, Cookie cookie) throws IOException {
		String domainAttr = null;
		boolean hostOnly = true;

		if (cookie instanceof ClientCookie) {
			ClientCookie clientCookie = (ClientCookie) cookie;
			domainAttr = clientCookie.getAttribute(ClientCookie.DOMAIN_ATTR);
			hostOnly = Objects.equals(cookie.getDomain(), domainAttr);
		}

		String cookieString = String.format("%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			domainAttr != null ? domainAttr : cookie.getDomain(),
			Boolean.valueOf(!hostOnly).toString().toUpperCase(),
			cookie.getPath(),
			Boolean.valueOf(cookie.isSecure()).toString().toUpperCase(),
			cookie.getExpiryDate() != null ? Long.valueOf(cookie.getExpiryDate().getTime() / 1000) : 0,
			cookie.getName(),
			cookie.getValue()
		);

		log.finer("Writing cookie: " + cookie);

		w.write(SERIALIZED_PREFIX);
		w.write(serialize(cookie));
		w.write(SERIALIZED_SUFFIX);
		w.write("\n");

		w.write(cookieString);
	}

	private Object deserialize(String serialized) throws IOException, ClassNotFoundException {
		byte[] base64Encoded = serialized.getBytes(charset);
		byte[] objectData = Base64.getUrlDecoder().decode(base64Encoded);
		try (
			ByteArrayInputStream bais = new ByteArrayInputStream(objectData);
			ObjectInputStream ois = new ObjectInputStream(bais);
		) {
			return ois.readObject();
		}
	}

	private String serialize(Object object) throws IOException {
		byte[] objectData;
		try (
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
		) {
			oos.writeObject(object);
			objectData = baos.toByteArray();
		}
		byte[] base64Encoded = Base64.getUrlEncoder().encode(objectData);
		String serialized = new String(base64Encoded, charset);
		return serialized;
	}

}
