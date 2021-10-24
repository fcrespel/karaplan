package me.crespel.karaplan.model.azlyrics;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class AzLyricsSuggestResponse {

	private String term;
	private List<AzLyricsSuggestion> songs;
	private List<AzLyricsSuggestion> artists;
	private List<AzLyricsSuggestion> albums;
	private List<AzLyricsSuggestion> lyrics;

}
