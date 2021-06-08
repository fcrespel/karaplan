package me.crespel.karaplan.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import me.crespel.karaplan.service.AbstractCatalogServiceIT;
import me.crespel.karaplan.service.CatalogService;

@SpringBootTest
@ActiveProfiles("test")
public class KvCatalogServiceImplIT extends AbstractCatalogServiceIT {

	public KvCatalogServiceImplIT(@Autowired @Qualifier("kvCatalog") CatalogService catalogService) {
		super(catalogService);
		this.testGetSongListQueryEnabled = false;
		this.testGetSongListStylesEnabled = false;
		this.testGetSongListThemeEnabled = false;
		this.testGetSongListTopEnabled = false;
		this.testGetSongListNewsEnabled = false;
		this.testGetSelectionEnabled = false;
		this.testGetSelectionListEnabled = false;
	}

}
