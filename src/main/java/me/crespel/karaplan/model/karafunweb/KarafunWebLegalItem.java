package me.crespel.karaplan.model.karafunweb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import tools.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import tools.jackson.dataformat.xml.annotation.JacksonXmlText;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebLegalItem {

	@JacksonXmlProperty(localName = "id", isAttribute = true)
	private Long id;

	@JacksonXmlProperty(localName = "type", isAttribute = true)
	private String type;

	@JacksonXmlText
	private String value;

}
