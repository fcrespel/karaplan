package me.crespel.karaplan.model.karafunweb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebFile {

	@JacksonXmlProperty(localName = "type", isAttribute = true)
	private String type;

	@JacksonXmlProperty(localName = "name")
	private String name;

	@JacksonXmlProperty(localName = "link")
	private String link;

	@JacksonXmlProperty(localName = "filesize")
	private Long fileSize;

	@JacksonXmlProperty(localName = "md5")
	private String md5;

}
