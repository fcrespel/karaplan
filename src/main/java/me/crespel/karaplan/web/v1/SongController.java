package me.crespel.karaplan.web.v1;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongComment;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.model.exception.BusinessException;
import me.crespel.karaplan.service.SongService;

@RestController
@RequestMapping(path = "/v1/songs", produces = MediaType.APPLICATION_JSON_VALUE)
public class SongController {

	@Autowired
	protected SongService songService;

	@GetMapping
	public Set<Song> getSongs() {
		return songService.findAll();
	}

	@GetMapping("/search")
	public Set<Song> search(@RequestParam String query, @RequestParam(required = false) Integer limit, @RequestParam(required = false) Integer offset) {
		return songService.search(query, limit, offset);
	}

	@GetMapping("/{catalogId}")
	public Song getSongByCatalogId(@PathVariable Long catalogId) {
		Optional<Song> song = songService.findByCatalogId(catalogId);
		if (song.isPresent()) {
			return song.get();
		} else {
			throw new BusinessException("Invalid song ID");
		}
	}

	@PostMapping("/{catalogId}")
	public Song importSongByCatalogId(@PathVariable Long catalogId) {
		Optional<Song> song = songService.findByCatalogId(catalogId);
		if (song.isPresent()) {
			return songService.save(song.get());
		} else {
			throw new BusinessException("Invalid song ID");
		}
	}

	@PostMapping("/{catalogId}/comment")
	public SongComment commentSongByCatalogId(@PathVariable Long catalogId, @RequestBody String comment) {
		Optional<Song> song = songService.findByCatalogId(catalogId);
		if (song.isPresent()) {
			return songService.addComment(song.get(), comment);
		} else {
			throw new BusinessException("Invalid song ID");
		}
	}

	@PostMapping("/{catalogId}/voteUp")
	public SongVote voteUpSongByCatalogId(@PathVariable Long catalogId) {
		Optional<Song> song = songService.findByCatalogId(catalogId);
		if (song.isPresent()) {
			return songService.voteUp(song.get());
		} else {
			throw new BusinessException("Invalid song ID");
		}
	}

	@PostMapping("/{catalogId}/voteDown")
	public SongVote voteDownSongByCatalogId(@PathVariable Long catalogId) {
		Optional<Song> song = songService.findByCatalogId(catalogId);
		if (song.isPresent()) {
			return songService.voteDown(song.get());
		} else {
			throw new BusinessException("Invalid song ID");
		}
	}

}
