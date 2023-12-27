package me.crespel.karaplan.model.karafunweb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
@JacksonXmlRootElement(localName = "response")
public class KarafunWebResponse {

	public static final String STATUS_DONE = "OK";
	public static final String STATUS_ERROR = "Error";
	public static final String ACTION_RESTART = "restart";
	public static final String ACTION_DISCONNECT = "disconnect";
	public static final String DISPLAY_NONE = "none";

	@JacksonXmlProperty(localName = "status", isAttribute = true)
	private String status;

	@JacksonXmlProperty(localName = "error")
	private KarafunWebError error;

	@JacksonXmlProperty(localName = "message")
	private KarafunWebMessage message;

	public boolean isDone() {
		return STATUS_DONE.equalsIgnoreCase(status);
	}

	public boolean isError() {
		return STATUS_ERROR.equalsIgnoreCase(status);
	}

	public boolean shouldRestart() {
		return error != null && ACTION_RESTART.equalsIgnoreCase(error.getAction());
	}

	public boolean shouldDisconnect() {
		return error != null && ACTION_DISCONNECT.equalsIgnoreCase(error.getAction());
	}

	@Data
	public static class KarafunWebError {
		@JacksonXmlProperty(localName = "action", isAttribute = true)
		private String action;

		@JacksonXmlText
		private String value;

		public String toString() {
			return value;
		}
	}

	@Data
	public static class KarafunWebMessage {
		@JacksonXmlProperty(localName = "action", isAttribute = true)
		private String display;

		@JacksonXmlText
		private String value;

		public String toString() {
			return value;
		}
	}

}
