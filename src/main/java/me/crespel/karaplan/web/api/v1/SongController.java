package me.crespel.karaplan.web.api.v1;

import java.util.Set;

import org.springdoc.core.annotations.ParameterObject;
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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import me.crespel.karaplan.domain.Playlist;
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.CatalogSelection;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSongFile;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.SongLyrics;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.CatalogService;
import me.crespel.karaplan.service.LyricsService;
import me.crespel.karaplan.service.PlaylistService;
import me.crespel.karaplan.service.SongService;

@RestController
@RequestMapping(path = "/api/v1/songs", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "songs", description = "Songs management")
public class SongController {

	@Autowired
	protected SongService songService;

	@Autowired
	protected CatalogService catalogService;

	@Autowired
	protected LyricsService lyricsService;

	@Autowired
	protected PlaylistService playlistService;

	@GetMapping
	@Operation(summary = "Get all songs")
	public Set<Song> getSongs(@ParameterObject @PageableDefault Pageable pageable) {
		return songService.findAll(pageable);
	}

	@GetMapping("/user")
	@Operation(summary = "Get all songs of current user")
	public Set<Song> getUserSongs(@ParameterObject @PageableDefault Pageable pageable, @AuthenticationPrincipal(expression = "user") User user) {
		return songService.findAllByUserId(user.getId(), pageable);
	}

	@GetMapping("/search")
	@Operation(summary = "Search songs in the catalog")
	public Set<Song> searchSongs(@RequestParam CatalogSongListType type, @RequestParam String query, @ParameterObject @PageableDefault Pageable pageable, @AuthenticationPrincipal(expression = "user") User user) {
		return songService.search(type, query, pageable, user.getLocaleParsed());
	}

	@GetMapping("/selections/{selectionType}")
	@Operation(summary = "Get song selections in the catalog")
	public Set<CatalogSelection> getSelections(@PathVariable CatalogSelectionType selectionType, @AuthenticationPrincipal(expression = "user") User user) {
		return catalogService.getSelectionList(selectionType, user.getLocaleParsed()).getSelections();
	}

	@GetMapping("/selections/{selectionType}/{selectionId}")
	@Operation(summary = "Get song selection information from the catalog")
	public CatalogSelection getSelection(@PathVariable CatalogSelectionType selectionType, @PathVariable Long selectionId, @AuthenticationPrincipal(expression = "user") User user) {
		return catalogService.getSelection(selectionType, selectionId, user.getLocaleParsed());
	}

	@GetMapping("/{catalogId}")
	@Operation(summary = "Get a song")
	public Song getSong(@PathVariable Long catalogId, @AuthenticationPrincipal(expression = "user") User user) {
		return songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
	}

	@PostMapping("/{catalogId}")
	@ResponseStatus(HttpStatus.CREATED)
	@Operation(summary = "Import a song from the catalog")
	public Song importSong(@PathVariable Long catalogId, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.save(song);
	}

	@GetMapping("/{catalogId}/lyrics")
	@Operation(summary = "Get a song's lyrics")
	public SongLyrics getSongLyrics(@PathVariable Long catalogId, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return lyricsService.getSongLyrics(song);
	}

	@GetMapping("/{catalogId}/files")
	@Operation(summary = "Get a song's files")
	public Set<CatalogSongFile> getSongFiles(@PathVariable Long catalogId, @AuthenticationPrincipal(expression = "user") User user) {
		return catalogService.getSongFileList(catalogId, user.getLocaleParsed()).getSongFiles();
	}

	@PostMapping("/{catalogId}/vote")
	@Operation(summary = "Vote for a song")
	public Song voteSong(@PathVariable Long catalogId, @RequestParam(defaultValue = "0") int score, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.vote(song, user, score);
	}

	@PostMapping("/{catalogId}/comment")
	@Operation(summary = "Add a comment to a song")
	public Song addCommentToSong(@PathVariable Long catalogId, @RequestBody String comment, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.addComment(song, user, comment);
	}

	@DeleteMapping("/{catalogId}/comment/{commentId}")
	@Operation(summary = "Remove a comment from a song")
	public Song removeCommentFromSong(@PathVariable Long catalogId, @PathVariable Long commentId, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.removeComment(song, user, commentId);
	}

	@PostMapping("/{catalogId}/playlist/{playlistId}")
	@Operation(summary = "Add a song to a playlist")
	public Song addSongToPlaylist(@PathVariable Long catalogId, @PathVariable Long playlistId, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
		Playlist playlist = playlistService.findById(playlistId).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		playlistService.addSong(playlist, song, user);
		return song;
	}

	@DeleteMapping("/{catalogId}/playlist/{playlistId}")
	@Operation(summary = "Remove a song from a playlist")
	public Song removeSongFromPlaylist(@PathVariable Long catalogId, @PathVariable Long playlistId, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId, user.getLocaleParsed()).orElseThrow(() -> new BusinessException("Invalid song ID"));
		Playlist playlist = playlistService.findById(playlistId).orElseThrow(() -> new BusinessException("Invalid playlist ID"));
		playlistService.removeSong(playlist, song, user);
		return song;
	}

}
