package me.crespel.karaplan.model.karafunweb;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebSong {

	@JacksonXmlProperty(localName = "id", isAttribute = true)
	private Long id;

	@JacksonXmlProperty(localName = "len", isAttribute = true)
	private Long length;

	@JacksonXmlProperty(localName = "pop", isAttribute = true)
	private Double popularity;

	@JacksonXmlProperty(localName = "bgcolor", isAttribute = true)
	private String backgroundColor;

	@JacksonXmlProperty(localName = "nbStreams", isAttribute = true)
	private Long nbStreams;

	@JacksonXmlProperty(localName = "preview-len", isAttribute = true)
	private Long previewLength;

	@JacksonXmlProperty(localName = "preview", isAttribute = true)
	private Integer preview;

	@JacksonXmlProperty(localName = "title")
	private String title;

	@JacksonXmlProperty(localName = "artist")
	private KarafunWebArtist artist;

	@JacksonXmlProperty(localName = "year")
	private Integer year;

	@JacksonXmlProperty(localName = "imagePath")
	private String imagePath;

	@JacksonXmlProperty(localName = "item")
	@JacksonXmlElementWrapper(localName = "legal")
	private List<KarafunWebLegalItem> legal;

	@JacksonXmlProperty(localName = "styles")
	private String styles;

}
