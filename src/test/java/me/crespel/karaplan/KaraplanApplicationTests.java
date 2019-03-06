package me.crespel.karaplan;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.service.CatalogService;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KaraplanApplicationTests {

	@Autowired
	protected CatalogService catalog;

	@Test
	public void contextLoads() {
	}

	@Test
	@Ignore
	public void getCatalogSong() {
		CatalogSong song = catalog.getSong(19237);
		System.out.println(song);
	}

	@Test
	@Ignore
	public void getCatalogSongList() {
		CatalogSongList songList = catalog.getSongList("muse", 2, 0);
		System.out.println(songList);
	}

}
