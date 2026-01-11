package me.crespel.karaplan.service.export;

import java.util.List;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Lists;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import me.crespel.karaplan.config.KarafunBarConfig.KarafunBarProperties;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.PlaylistSong;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.service.ExportService;

@Slf4j
@Service("karafunBarExport")
public class KarafunBarExportServiceImpl implements ExportService {

	private static final String PLAYLIST_HASH_HEADER = "X-Playlist-Hash";

	private final KarafunBarProperties properties;
	private final RestClient restClient;

	public KarafunBarExportServiceImpl(KarafunBarProperties properties, RestClient.Builder restClientBuilder) {
		this.properties = properties;
		this.restClient = restClientBuilder
				.defaultHeader(HttpHeaders.USER_AGENT, properties.getUserAgent())
				.build();
	}

	@Override
	public void exportPlaylist(Playlist playlist, String target) {
		if (playlist.getSongs() != null && !playlist.getSongs().isEmpty()) {
			try {
				UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(properties.getEndpoint())
						.path("/" + target + "/playlist/list");

				// Retrieve the current playlist to get the playlist hash
				log.debug("Getting current playlist for ID {}", target);
				ResponseEntity<List<PlaylistEntry>> getResponse = restClient.get()
						.uri(builder.build().encode().toUri())
						.retrieve()
						.toEntity(new ParameterizedTypeReference<List<PlaylistEntry>>() {});
				log.debug("Get playlist response for ID {}: {}", target, getResponse);
				if (getResponse.getStatusCode().isError()) {
					throw new TechnicalException("Failed to get playlist for ID " + target + ": HTTP error " + getResponse.getStatusCode());
				}
				String playlistHash = getResponse.getHeaders().getFirst(PLAYLIST_HASH_HEADER);

				// Update the playlist
				List<SongAndSinger> songList = buildSongList(playlist.getSongs());
				log.debug("Posting playlist for ID {}: {}", target, songList);
				ResponseEntity<List<PlaylistEntry>> postResponse = restClient.post()
						.uri(builder.build().encode().toUri())
						.header(PLAYLIST_HASH_HEADER, playlistHash)
						.body(songList)
						.retrieve()
						.toEntity(new ParameterizedTypeReference<List<PlaylistEntry>>() {});
				log.debug("Post playlist response for ID {}: {}", target, postResponse);
				if (postResponse.getStatusCode().isError()) {
					throw new TechnicalException("Failed to post playlist for ID " + target + ": HTTP error " + postResponse.getStatusCode());
				}

			} catch (RestClientException e) {
				throw new TechnicalException(e);
			}
		}
	}

	private List<SongAndSinger> buildSongList(Set<PlaylistSong> playlistSongs) {
		List<SongAndSinger> list = Lists.newArrayList();
		for (PlaylistSong playlistSong : playlistSongs) {
			list.add(new SongAndSinger(playlistSong.getSong().getCatalogId(), ""));
		}
		return list;
	}

	@Data
	@Accessors(chain = true)
	@JsonIgnoreProperties(ignoreUnknown = true)
	public static class PlaylistEntry {
		private Integer rank;
		private PlaylistEntrySong song;
	}

	@Data
	@Accessors(chain = true)
	@JsonIgnoreProperties(ignoreUnknown = true)
	public static class PlaylistEntrySong {
		private Long id;
		private String name;
	}

	@Data
	@AllArgsConstructor
	@Accessors(chain = true)
	@JsonIgnoreProperties(ignoreUnknown = true)
	public static class SongAndSinger {
		private Long song;
		private String singer;
	}

}
