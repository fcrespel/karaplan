package me.crespel.karaplan.model;

import java.io.Serializable;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogSongFileList implements Serializable {

	private static final long serialVersionUID = -5664455045281211629L;

	private Long length;
	private Set<CatalogSongFile> songFiles;

}
