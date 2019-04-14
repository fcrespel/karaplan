package me.crespel.karaplan.web.api.v1;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
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
import me.crespel.karaplan.model.CatalogSelection;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSongFile;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.CatalogService;
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongService;
import springfox.documentation.annotations.ApiIgnore;

@RestController
@RequestMapping(path = "/api/v1/songs", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "songs", description = "Songs management")
public class SongController {

	@Autowired
	protected SongService songService;

	@Autowired
	protected CatalogService catalogService;

	@Autowired
	protected PlaylistService playlistService;

	@GetMapping
	@ApiOperation("Get all songs")
	public Set<Song> getSongs(@PageableDefault Pageable pageable) {
		return songService.findAll(pageable);
	}

	@GetMapping("/search")
	@ApiOperation("Search songs in the catalog")
	public Set<Song> searchSongs(@RequestParam CatalogSongListType type, @RequestParam String query, @PageableDefault Pageable pageable) {
		return songService.search(type, query, pageable);
	}

	@GetMapping("/selections")
	@ApiOperation("Get song selections in the catalog")
	public Set<CatalogSelection> getSelections(@RequestParam CatalogSelectionType type) {
		return catalogService.getSelectionList(type).getSelections();
	}

	@GetMapping("/{catalogId}")
	@ApiOperation("Get a song")
	public Song getSong(@PathVariable Long catalogId) {
		return songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
	}

	@PostMapping("/{catalogId}")
	@ResponseStatus(HttpStatus.CREATED)
	@ApiOperation("Import a song from the catalog")
	public Song importSong(@PathVariable Long catalogId) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.save(song);
	}

	@GetMapping("/{catalogId}/files")
	@ApiOperation("Get a song's files")
	public Set<CatalogSongFile> getSongFiles(@PathVariable Long catalogId) {
		return catalogService.getSongFileList(catalogId).getSongFiles();
	}

	@PostMapping("/{catalogId}/vote")
	@ApiOperation("Vote for a song")
	public Song voteSong(@PathVariable Long catalogId, @RequestParam(defaultValue = "0") int score, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.vote(song, user, score);
	}

	@PostMapping("/{catalogId}/comment")
	@ApiOperation("Add a comment to a song")
	public Song addCommentToSong(@PathVariable Long catalogId, @RequestBody String comment, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.addComment(song, user, comment);
	}

	@DeleteMapping("/{catalogId}/comment/{commentId}")
	@ApiOperation("Remove a comment from a song")
	public Song removeCommentFromSong(@PathVariable Long catalogId, @PathVariable Long commentId, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.removeComment(song, user, commentId);
	}

	@PostMapping("/{catalogId}/playlist/{playlistId}")
	@ApiOperation("Add a song to a playlist")
	public Song addSongToPlaylist(@PathVariable Long catalogId, @PathVariable Long playlistId, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		Playlist playlist = playlistService.findById(playlistId).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		playlistService.addSong(playlist, song, user);
		return song;
	}

	@DeleteMapping("/{catalogId}/playlist/{playlistId}")
	@ApiOperation("Remove a song from a playlist")
	public Song removeSongFromPlaylist(@PathVariable Long catalogId, @PathVariable Long playlistId, @ApiIgnore @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		Playlist playlist = playlistService.findById(playlistId).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		playlistService.removeSong(playlist, song, user);
		return song;
	}

}
