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
public class KarafunWebPlaylistList {

	@JacksonXmlProperty(localName = "count", isAttribute = true)
	private Long count;

	@JacksonXmlProperty(localName = "total", isAttribute = true)
	private Long total;

	@JacksonXmlProperty(localName = "playlist")
	@JacksonXmlElementWrapper(useWrapping = false)
	private List<KarafunWebPlaylist> playlists;

}
