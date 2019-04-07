package me.crespel.karaplan.web.api.v1;

import java.security.Principal;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import me.crespel.karaplan.service.ExportService;
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

	@Autowired
	@Qualifier("karafunRemoteExport")
	protected ExportService karafunRemoteExportService;

	@Autowired
	@Qualifier("karafunBarExport")
	protected ExportService karafunBarExportService;

	@GetMapping
	@ApiOperation("Get all playlists")
	public Set<Playlist> getPlaylists(@PageableDefault Pageable pageable) {
		return playlistService.findAll(pageable);
	}
	
	@GetMapping("/authorized")
	@ApiOperation("Get all authorized playlists")
	public Set<Playlist> getAuthorizedPlaylists(@PageableDefault Pageable pageable, Principal user) {
		return playlistService.getAuthorizedPlaylists(pageable, user.getName());
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	@ApiOperation("Create a playlist")
	public Playlist createPlaylist(@RequestParam String name, @RequestParam(required = false, defaultValue = "false") boolean restricted, Principal user) {
		return playlistService.createPlaylist(name, user.getName(), restricted);
	}

	@GetMapping("/{playlistId}")
	@ApiOperation("Get a playlist")
	public Playlist getPlaylist(@PathVariable Long playlistId) {
		return playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
	}
	
	@GetMapping("/{playlistId}/unlock")
	@ApiOperation("Get a playlist")
	public void addUserToPlaylist(@PathVariable Long playlistId, @RequestParam String accessKey, Principal user) {
		playlistService.addUserToPlaylist(playlistId, accessKey, user.getName());
	}

	@DeleteMapping("/{playlistId}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	@ApiOperation("Delete a playlist")
	public void deletePlaylist(@PathVariable Long playlistId) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		playlistService.delete(playlist);
	}

	@PostMapping("/{playlistId}/song/{catalogId}")
	@ApiOperation("Add a song to a playlist")
	public Playlist addSongToPlaylist(@PathVariable Long playlistId, @PathVariable Long catalogId) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return playlistService.addSong(playlist, song);
	}

	@DeleteMapping("/{playlistId}/song/{catalogId}")
	@ApiOperation("Remove a song from a playlist")
	public Playlist removeSongFromPlaylist(@PathVariable Long playlistId, @PathVariable Long catalogId) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return playlistService.removeSong(playlist, song);
	}

	@PostMapping("/{playlistId}/export/karafun/{remoteId}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	@ApiOperation("Export a playlist to Karafun Remote")
	public void exportPlaylistToKarafunRemote(@PathVariable Long playlistId, @PathVariable String remoteId) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		karafunRemoteExportService.exportPlaylist(playlist, remoteId);
	}

	@PostMapping("/{playlistId}/export/karafunbar/{bookingId}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	@ApiOperation("Export a playlist to Karafun Bar")
	public void exportPlaylistToKarafunBar(@PathVariable Long playlistId, @PathVariable String bookingId) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		karafunBarExportService.exportPlaylist(playlist, bookingId);
	}

}
