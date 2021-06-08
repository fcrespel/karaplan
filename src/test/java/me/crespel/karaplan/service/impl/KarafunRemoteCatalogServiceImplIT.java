package me.crespel.karaplan.service.impl;

import org.junit.jupiter.api.Disabled;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import me.crespel.karaplan.service.AbstractCatalogServiceIT;
import me.crespel.karaplan.service.CatalogService;

@Disabled // KaraFun Remote no longer allows arbitrary remote codes :-(
@SpringBootTest
@ActiveProfiles("test")
public class KarafunRemoteCatalogServiceImplIT extends AbstractCatalogServiceIT {

	public KarafunRemoteCatalogServiceImplIT(@Autowired @Qualifier("karafunRemoteCatalog") CatalogService catalogService) {
		super(catalogService);
		this.testGetArtistEnabled = false;
		this.testGetSongFileListEnabled = false;
	}

}
