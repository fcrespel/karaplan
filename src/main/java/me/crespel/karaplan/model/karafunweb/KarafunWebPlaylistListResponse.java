package me.crespel.karaplan.model.karafunweb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebPlaylistListResponse extends KarafunWebResponse {

	@JacksonXmlProperty(localName = "playlists")
	private KarafunWebPlaylistList playlists;

}
