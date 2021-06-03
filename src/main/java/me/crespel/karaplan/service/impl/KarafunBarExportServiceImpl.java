package me.crespel.karaplan.service.impl;

import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Lists;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import me.crespel.karaplan.config.KarafunConfig.KarafunBarProperties;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.PlaylistSong;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.model.karafunremote.KarafunRemoteSong;
import me.crespel.karaplan.service.ExportService;

@Slf4j
@Service("karafunBarExport")
public class KarafunBarExportServiceImpl implements ExportService {

	private static final String PLAYLIST_HASH_HEADER = "X-Playlist-Hash";

	@Autowired
	protected KarafunBarProperties properties;

	@Autowired
	private RestTemplate restTemplate;

	@Override
	public void exportPlaylist(Playlist playlist, String target) {
		if (playlist.getSongs() != null && !playlist.getSongs().isEmpty()) {
			try {
				UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.getEndpoint())
						.path("/" + target + "/playlist/list");

				log.debug("Getting current playlist for ID {}", target);
				ResponseEntity<List<PlaylistEntry>> getResponse = restTemplate.exchange(builder.build().encode().toUri(), HttpMethod.GET, null, new ParameterizedTypeReference<List<PlaylistEntry>>() {});
				log.debug("Get playlist response for ID {}: {}", target, getResponse);
				if (getResponse.getStatusCode().isError()) {
					throw new TechnicalException("Failed to get playlist for ID " + target + ": HTTP error " + getResponse.getStatusCode());
				}
				String playlistHash = getResponse.getHeaders().getFirst(PLAYLIST_HASH_HEADER);

				List<SongAndSinger> songList = buildSongList(playlist.getSongs());
				HttpHeaders songHeaders = new HttpHeaders();
				songHeaders.add(PLAYLIST_HASH_HEADER, playlistHash);
				HttpEntity<List<SongAndSinger>> postRequest = new HttpEntity<>(songList, songHeaders);
				log.debug("Posting playlist for ID {}: {}", target, postRequest);
				ResponseEntity<List<PlaylistEntry>> postResponse = restTemplate.exchange(builder.build().encode().toUri(), HttpMethod.POST, postRequest, new ParameterizedTypeReference<List<PlaylistEntry>>() {});
				log.debug("Post playlist response for ID {}: {}", target, postResponse);
				if (postResponse.getStatusCode().isError()) {
					throw new TechnicalException("Failed to post playlist for ID " + target + ": HTTP error " + postResponse.getStatusCode());
				}

			} catch (RestClientException e) {
				throw new TechnicalException(e);
			}
		}
	}

	protected List<SongAndSinger> buildSongList(Set<PlaylistSong> playlistSongs) {
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
		private KarafunRemoteSong song;
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
