package me.crespel.karaplan.web.api.v1;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongComment;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.SongService;

@RestController
@RequestMapping(path = "/api/v1/songs", produces = MediaType.APPLICATION_JSON_VALUE)
@Api(tags = "songs", description = "Songs management")
public class SongController {

	@Autowired
	protected SongService songService;

	@GetMapping
	@ApiOperation("Get all songs")
	public Set<Song> getSongs(@PageableDefault Pageable pageable) {
		return songService.findAll(pageable);
	}

	@GetMapping("/search")
	@ApiOperation("Search songs in the catalog")
	public Set<Song> search(@RequestParam String query, @PageableDefault Pageable pageable) {
		return songService.search(query, pageable);
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

	@PostMapping("/{catalogId}/comment")
	@ResponseStatus(HttpStatus.CREATED)
	@ApiOperation("Add a comment to a song by catalog id")
	public SongComment commentSongByCatalogId(@PathVariable Long catalogId, @RequestBody String comment, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.addComment(song, user, comment);
	}

	@PostMapping("/{catalogId}/vote")
	@ApiOperation("Vote for a song by catalog id")
	public SongVote voteSongByCatalogId(@PathVariable Long catalogId, @RequestParam(defaultValue = "0") int score, @AuthenticationPrincipal(expression = "user") User user) {
		Song song = songService.findByCatalogId(catalogId).orElseThrow(() -> new BusinessException("Invalid song ID"));
		return songService.vote(song, user, score);
	}

}
