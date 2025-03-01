package me.crespel.karaplan.service.lyrics;

import java.time.Duration;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.extern.slf4j.Slf4j;
import me.crespel.karaplan.config.AzLyricsConfig.AzLyricsProperties;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.model.SongLyrics;
import me.crespel.karaplan.model.azlyrics.AzLyricsSuggestResponse;
import me.crespel.karaplan.model.azlyrics.AzLyricsSuggestion;
import me.crespel.karaplan.service.LyricsService;

@Slf4j
@Service("azLyrics")
@CacheConfig(cacheNames = "azLyricsCache")
public class AzLyricsServiceImpl implements LyricsService {

	private static final String SOURCE_NAME = "AZLyrics";
	private static final Pattern LYRICS_HTML_PATTERN = Pattern.compile("<div>\\s*<!-- Usage of [^\n]+ -->\\s*(.*?)\\s*</div>", Pattern.DOTALL);

	private final AzLyricsProperties properties;
	private final RestTemplate restTemplate;

	public AzLyricsServiceImpl(AzLyricsProperties properties, RestTemplateBuilder restTemplateBuilder) {
		this.properties = properties;
		this.restTemplate = restTemplateBuilder
				.connectTimeout(Duration.ofMillis(properties.getConnectTimeout()))
				.readTimeout(Duration.ofMillis(properties.getReadTimeout()))
				.defaultHeader(HttpHeaders.USER_AGENT, properties.getUserAgent())
				.additionalMessageConverters(jacksonMessageConverter())
				.build();
	}

	private static HttpMessageConverter<?> jacksonMessageConverter() {
		MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
		converter.setSupportedMediaTypes(Arrays.asList(MediaType.APPLICATION_JSON, MediaType.TEXT_HTML));
		return converter;
	}

	@Override
	@Cacheable
	public SongLyrics getSongLyrics(Song song) {
		SongLyrics lyrics = new SongLyrics();
		AzLyricsSuggestResponse suggestions = getSuggestions(song);
		if (suggestions != null && suggestions.getSongs() != null && !suggestions.getSongs().isEmpty()) {
			AzLyricsSuggestion suggestion = suggestions.getSongs().get(0);
			if (suggestion.getUrl() != null && suggestion.getUrl().startsWith(properties.getBaseUrl())) {
				String lyricsHtml = restTemplate.getForObject(suggestion.getUrl(), String.class);
				Matcher lyricsMatcher = LYRICS_HTML_PATTERN.matcher(lyricsHtml);
				if (lyricsMatcher.find()) {
					lyrics.setLyrics(lyricsMatcher.group(1).replaceAll("[\\n\\r]", "").replaceAll("<br/?>", "\n").replaceAll("</?[^>]+>", ""));
					lyrics.setSource(SOURCE_NAME);
					lyrics.setUrl(suggestion.getUrl());
				}
			}
		}
		return lyrics;
	}

	private AzLyricsSuggestResponse getSuggestions(Song song) {
		try {
			UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(properties.getEndpoint())
					.queryParam("q", song.getName() + " - " + song.getArtist().getName());
			return restTemplate.getForObject(builder.build().encode().toUri(), AzLyricsSuggestResponse.class);
		} catch (RestClientException e) {
			log.error("Failed to retrieve lyrics from AZLyrics for {}", song, e);
			return null;
		}
	}

}
