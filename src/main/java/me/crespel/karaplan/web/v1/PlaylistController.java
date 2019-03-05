package me.crespel.karaplan.web.v1;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.PlaylistService;

@RestController
@RequestMapping(path = "/v1/playlists", produces = MediaType.APPLICATION_JSON_VALUE)
public class PlaylistController {

	@Autowired
	protected PlaylistService playlistService;
	
	@GetMapping
	public Set<Playlist> getPlaylists() {
		return playlistService.findAll();
	}

	@GetMapping("/{id}")
	public Playlist getPlaylist(@PathVariable Long id) {
		Optional<Playlist> playlist = playlistService.findById(id);
		if (playlist.isPresent()) {
			return playlist.get();
		} else {
			throw new BusinessException("Invalid playlist ID");
		}
	}

}
