package me.crespel.karaplan.service.lyrics;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.extern.slf4j.Slf4j;
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
	private static final String BASE_URL = "https://www.azlyrics.com";
	private static final String SEARCH_URL = "https://search.azlyrics.com/suggest.php";
	private static final Pattern LYRICS_HTML_PATTERN = Pattern.compile("<div>\\s*<!-- Usage of [^\n]+ -->\\s*(.*?)\\s*</div>", Pattern.DOTALL);

	private final RestTemplate restTemplate;

	public AzLyricsServiceImpl(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}

	@Override
	@Cacheable
	public SongLyrics getSongLyrics(Song song) {
		SongLyrics lyrics = new SongLyrics();
		AzLyricsSuggestResponse suggestions = getSuggestions(song);
		if (suggestions != null && suggestions.getSongs() != null && !suggestions.getSongs().isEmpty()) {
			AzLyricsSuggestion suggestion = suggestions.getSongs().get(0);
			if (suggestion.getUrl() != null && suggestion.getUrl().startsWith(BASE_URL)) {
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
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(SEARCH_URL)
					.queryParam("q", song.getName() + " - " + song.getArtist().getName());
			return restTemplate.getForObject(builder.build().encode().toUri(), AzLyricsSuggestResponse.class);
		} catch (RestClientException e) {
			log.error("Failed to retrieve lyrics from AZLyrics for {}", song, e);
			return null;
		}
	}

}
