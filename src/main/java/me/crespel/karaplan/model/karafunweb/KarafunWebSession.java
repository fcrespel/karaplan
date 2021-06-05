package me.crespel.karaplan.model.karafunweb;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebSession {

	@JsonIgnore
	private Locale locale;

	@JacksonXmlProperty(localName = "version")
	private String version;

	@JacksonXmlProperty(localName = "key")
	private String sessionKey;

	@JacksonXmlProperty(localName = "querykey")
	private Long queryKey;

	@JacksonXmlProperty(localName = "plan")
	private String plan;

	@JacksonXmlProperty(localName = "user_id")
	private String userId;

	public KarafunWebSession() {
		this.reset();
	}

	public KarafunWebSession(Locale locale) {
		this();
		this.locale = locale;
	}

	public boolean isValid() {
		return sessionKey != null && !sessionKey.equals("null") && queryKey != null;
	}

	public synchronized void init(String sessionKey, Long queryKey) {
		this.sessionKey = sessionKey;
		this.queryKey = queryKey;
	}

	public synchronized void reset() {
		this.sessionKey = "null";
		this.queryKey = null;
	}

	public synchronized String getNextQueryKey() {
		if (queryKey != null) {
			queryKey = 32717L * queryKey + 577L;
			queryKey &= 4294967295L; // Cap to 32 bits
			return Long.toString(queryKey);
		} else {
			return "";
		}
	}

}
