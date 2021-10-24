package me.crespel.karaplan.model.azlyrics;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class AzLyricsSuggestion {

	private String url;
	private String autocomplete;

}
