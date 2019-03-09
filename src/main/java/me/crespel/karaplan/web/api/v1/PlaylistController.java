package me.crespel.karaplan.web.api.v1;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongService;

@RestController
@RequestMapping(path = "/api/v1/playlists", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "playlists", description = "Playlists management")
public class PlaylistController {

	@Autowired
	protected PlaylistService playlistService;

	@Autowired
	protected SongService songService;

	@GetMapping
	@ApiOperation("Get all playlists")
	public Set<Playlist> getPlaylists(@PageableDefault Pageable pageable) {
		return playlistService.findAll(pageable);
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	@ApiOperation("Create a playlist")
	public Playlist createPlaylist(@RequestParam String name) {
		return playlistService.save(new Playlist().setName(name));
	}

	@GetMapping("/{id}")
	@ApiOperation("Get a playlist by id")
	public Playlist getPlaylist(@PathVariable Long id) {
		return playlistService.findById(id).orElseThrow(() -> new BusinessException("Invalid playlist ID")); 
	}

	@PostMapping("/{id}/song/{catalogId}")
	@ApiOperation("Add a song to a playlist by catalog id")
	public Playlist addSongById(@PathVariable Long id, @PathVariable Long catalogId) {
		Playlist playlist = playlistService.findById(id).orElseThrow(() -> new BusinessException("Invalid playlist ID")); 
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		playlist.getSongs().add(song);
		return playlistService.save(playlist);
	}

	@DeleteMapping("/{id}/song/{catalogId}")
	@ApiOperation("Remove a song from a playlist by catalog id")
	public Playlist removeSongById(@PathVariable Long id, @PathVariable Long catalogId) {
		Playlist playlist = playlistService.findById(id).orElseThrow(() -> new BusinessException("Invalid playlist ID")); 
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		playlist.getSongs().remove(song);
		return playlistService.save(playlist);
	}

}
