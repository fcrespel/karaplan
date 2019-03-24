package me.crespel.karaplan.model.kv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.ToString;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@ToString(of = {"id", "songId", "artistId", "trackType"})
@JsonIgnoreProperties(ignoreUnknown = true)
public class KvSongFile {

	private Long id;
	private Long songId;
	private Long artistId;
	private String songUrl;
	private String previewUrl;
	private String format;
	private String trackType;
	private Double price;
	private String currency;

}
