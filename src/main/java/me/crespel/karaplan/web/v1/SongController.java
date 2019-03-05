package me.crespel.karaplan.web.v1;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import me.crespel.karaplan.domain.Song;
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

	@GetMapping("/{id}")
	public Song getSong(@PathVariable Long id) {
		Optional<Song> song = songService.findById(id);
		if (song.isPresent()) {
			return song.get();
		} else {
			throw new BusinessException("Invalid song ID");
		}
	}

}
