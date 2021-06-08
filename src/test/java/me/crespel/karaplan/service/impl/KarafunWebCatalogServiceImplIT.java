package me.crespel.karaplan.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import me.crespel.karaplan.service.AbstractCatalogServiceIT;
import me.crespel.karaplan.service.CatalogService;

@SpringBootTest
@ActiveProfiles("test")
public class KarafunWebCatalogServiceImplIT extends AbstractCatalogServiceIT {

	public KarafunWebCatalogServiceImplIT(@Autowired @Qualifier("karafunWebCatalog") CatalogService catalogService) {
		super(catalogService);
		this.testGetArtistEnabled = false;
		this.testGetSongFileListEnabled = false;
	}

}
