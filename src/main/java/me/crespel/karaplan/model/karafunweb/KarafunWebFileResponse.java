package me.crespel.karaplan.model.karafunweb;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@EqualsAndHashCode(callSuper = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class KarafunWebFileResponse extends KarafunWebResponse {

	@JacksonXmlProperty(localName = "file")
	@JacksonXmlElementWrapper(useWrapping = false)
	private List<KarafunWebFile> files;

}
