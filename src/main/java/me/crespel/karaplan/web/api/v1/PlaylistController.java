package me.crespel.karaplan.web.api.v1;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.PlaylistSortDirection;
import me.crespel.karaplan.model.PlaylistSortType;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.model.exception.TechnicalException;
import me.crespel.karaplan.service.ExportService;
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongService;
import springfox.documentation.annotations.ApiIgnore;

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

	@Autowired
	@Qualifier("csvExport")
	protected ExportService csvExportService;

	@GetMapping
	@ApiOperation("Get all playlists")
	public Set<Playlist> getPlaylists(@PageableDefault Pageable pageable, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		return playlistService.findAll(pageable, user);
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	@ApiOperation("Create a playlist")
	public Playlist createPlaylist(@RequestParam String name, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		return playlistService.create(name, user);
	}

	@GetMapping("/{playlistId}")
	@ApiOperation("Get a playlist")
	public Playlist getPlaylist(@PathVariable Long playlistId, @RequestParam(required = false) String accessKey, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		return playlistService.findById(playlistId, true, user, accessKey).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
	}

	@PutMapping("/{playlistId}")
	@ApiOperation("Save a playlist")
	public Playlist savePlaylist(@PathVariable Long playlistId, @RequestBody Playlist playlist, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Playlist playlistToSave = playlistService.findById(playlistId).orElseThrow(() -> new BusinessException("Invalid playlist ID"))
				.setName(playlist.getName())
				.setReadOnly(playlist.getReadOnly());
		return playlistService.save(playlistToSave, user);
	}

	@PostMapping("/{playlistId}/join")
	@ApiOperation("Add the current user to a playlist with the given access key")
	public Playlist addUserToPlaylist(@PathVariable Long playlistId, @RequestParam String accessKey, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		return playlistService.addUser(playlist, user, accessKey);
	}

	@PostMapping("/{playlistId}/leave")
	@ApiOperation("Remove the current user from a playlist")
	public Playlist addUserToPlaylist(@PathVariable Long playlistId, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		return playlistService.removeUser(playlist, user);
	}

	@PostMapping("/{playlistId}/song/{catalogId}")
	@ApiOperation("Add a song to a playlist")
	public Playlist addSongToPlaylist(@PathVariable Long playlistId, @PathVariable Long catalogId, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return playlistService.addSong(playlist, song, user);
	}

	@DeleteMapping("/{playlistId}/song/{catalogId}")
	@ApiOperation("Remove a song from a playlist")
	public Playlist removeSongFromPlaylist(@PathVariable Long playlistId, @PathVariable Long catalogId, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return playlistService.removeSong(playlist, song, user);
	}

	@PostMapping("/{playlistId}/sort")
	@ApiOperation("Sort a playlist's songs according to a type and direction")
	public Playlist sortPlaylist(@PathVariable Long playlistId, @RequestParam PlaylistSortType sortType, @RequestParam(defaultValue = "asc") PlaylistSortDirection sortDirection, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		return playlistService.sort(playlist, sortType, sortDirection, user);
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

	@GetMapping("/{playlistId}/export/csv")
	@ApiOperation("Export a playlist to a CSV file")
	public ResponseEntity<Resource> exportPlaylistToKarafunBar(@PathVariable Long playlistId) {
		Playlist playlist = playlistService.findById(playlistId, true).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		File csvFile = null;
		try {
			csvFile = File.createTempFile("karaplan", ".csv");
			csvExportService.exportPlaylist(playlist, csvFile.getAbsolutePath());
			Resource resource = new ByteArrayResource(Files.readAllBytes(csvFile.toPath()));
			String csvFileName = playlist.getName().replace("\"", "");
			return ResponseEntity.ok()
					.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"Playlist " + csvFileName + ".csv\"")
					.contentType(MediaType.TEXT_PLAIN)
					.contentLength(csvFile.length())
					.body(resource);
		} catch (IOException e) {
			throw new TechnicalException(e);
		} finally {
			if (csvFile != null) {
				csvFile.delete();
			}
		}
	}

}
