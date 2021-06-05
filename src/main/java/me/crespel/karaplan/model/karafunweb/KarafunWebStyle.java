package me.crespel.karaplan.model.karafunweb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlText;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebStyle {

	@JacksonXmlProperty(localName = "filter", isAttribute = true)
	private String filter;

	@JacksonXmlProperty(localName = "count", isAttribute = true)
	private Long count;

	@JacksonXmlProperty(localName = "image_id", isAttribute = true)
	private String imageId;

	@JacksonXmlText
	private String name;

}
