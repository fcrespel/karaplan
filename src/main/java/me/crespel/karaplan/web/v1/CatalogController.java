package me.crespel.karaplan.web.v1;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.service.CatalogService;

@RestController
@RequestMapping(path = "/v1/catalog", produces = MediaType.APPLICATION_JSON_VALUE)
public class CatalogController {

	@Autowired
	protected CatalogService catalogService;

	@GetMapping("/search")
	public CatalogSongList search(@RequestParam String query, @RequestParam(required = false) Integer limit, @RequestParam(required = false) Integer offset) {
		return catalogService.getSongList(query, limit, offset);
	}

	@GetMapping("/songs/{songId}")
	public CatalogSong getSongById(@PathVariable Long songId) {
		return catalogService.getSongInfo(songId);
	}

}
