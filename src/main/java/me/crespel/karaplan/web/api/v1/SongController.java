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
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongService;

@RestController
@RequestMapping(path = "/api/v1/songs", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "songs", description = "Songs management")
public class SongController {

	@Autowired
	protected SongService songService;

	@Autowired
	protected PlaylistService playlistService;

	@GetMapping
	@ApiOperation("Get all songs")
	public Set<Song> getSongs(@PageableDefault Pageable pageable) {
		return songService.findAll(pageable);
	}

	@GetMapping("/search")
	@ApiOperation("Search songs in the catalog by type")
	public Set<Song> search(@RequestParam CatalogSongListType type, @RequestParam String query, @PageableDefault Pageable pageable) {
		return songService.search(type, query, pageable);
	}

	@GetMapping("/selections")
	@ApiOperation("Get song selections by type")
	public Set<CatalogSelection> getSelections(@RequestParam CatalogSelectionType type) {
		return songService.getSelections(type);
	}

	@GetMapping("/{catalogId}")
	@ApiOperation("Get a song by catalog id")
	public Song getSongByCatalogId(@PathVariable Long catalogId) {
		return songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
	}

	@PostMapping("/{catalogId}")
	@ResponseStatus(HttpStatus.CREATED)
	@ApiOperation("Import a song from catalog id")
	public Song importSongByCatalogId(@PathVariable Long catalogId) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.save(song);
	}

	@PostMapping("/{catalogId}/vote")
	@ApiOperation("Vote for a song by catalog id")
	public Song voteSongByCatalogId(@PathVariable Long catalogId, @RequestParam(defaultValue = "0") int score, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.vote(song, user, score);
	}

	@PostMapping("/{catalogId}/comment")
	@ApiOperation("Add a comment to a song by catalog id")
	public Song commentSongByCatalogId(@PathVariable Long catalogId, @RequestBody String comment, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.addComment(song, user, comment);
	}

	@PostMapping("/{catalogId}/playlist/{playlistId}")
	@ApiOperation("Add a song to a playlist by catalog id")
	public Song addSongToPlaylistByCatalogId(@PathVariable Long catalogId, @PathVariable Long playlistId) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		Playlist playlist = playlistService.findById(playlistId).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		playlistService.addSong(playlist, song);
		return song;
	}

	@DeleteMapping("/{catalogId}/playlist/{playlistId}")
	@ApiOperation("Remove a song from a playlist by catalog id")
	public Song removeSongFromPlaylistByCatalogId(@PathVariable Long catalogId, @PathVariable Long playlistId) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		Playlist playlist = playlistService.findById(playlistId).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		playlistService.removeSong(playlist, song);
		return song;
	}

}
