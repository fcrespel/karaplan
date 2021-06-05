package me.crespel.karaplan.model.karafunweb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebPlaylist {

	@JacksonXmlProperty(localName = "id", isAttribute = true)
	private Long id;

	@JacksonXmlProperty(localName = "title", isAttribute = true)
	private String title;

	@JacksonXmlProperty(localName = "image", isAttribute = true)
	private String image;

	@JacksonXmlProperty(localName = "image_id", isAttribute = true)
	private String imageId;

	@JacksonXmlProperty(localName = "pop", isAttribute = true)
	private Double popularity;

}
