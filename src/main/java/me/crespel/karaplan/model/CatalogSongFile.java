package me.crespel.karaplan.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@ToString(of = {"id", "songId", "artistId", "trackType"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogSongFile implements Serializable {

	private static final long serialVersionUID = 7165858572630331468L;

	private Long id;
	private Long songId;
	private Long artistId;
	private String catalogUrl;
	private String previewUrl;
	private String format;
	private String trackType;

}
