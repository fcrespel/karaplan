package me.crespel.karaplan.web.v1;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongService;

@RestController
@RequestMapping(path = "/v1/playlists", produces = MediaType.APPLICATION_JSON_VALUE)
public class PlaylistController {

	@Autowired
	protected PlaylistService playlistService;

	@Autowired
	protected SongService songService;

	@GetMapping
	public Set<Playlist> getPlaylists() {
		return playlistService.findAll();
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public Playlist createPlaylist(@RequestParam String name) {
		Playlist playlist = new Playlist();
		playlist.setName(name);
		return playlistService.save(playlist);
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

	@PostMapping("/{id}/{songId}")
	public Playlist addSongById(@PathVariable Long id, @PathVariable Long songId) {
		Optional<Playlist> playlist = playlistService.findById(id);
		if (playlist.isPresent()) {
			Optional<Song> song = songService.findById(songId);
			if (song.isPresent()) {
				playlist.get().getSongs().add(song.get());
				return playlistService.save(playlist.get());
			} else {
				throw new BusinessException("Invalid song ID");
			}
		} else {
			throw new BusinessException("Invalid playlist ID");
		}
	}

}
