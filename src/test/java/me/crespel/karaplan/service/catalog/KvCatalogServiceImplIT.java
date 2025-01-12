package me.crespel.karaplan.service.catalog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
public class KvCatalogServiceImplIT extends AbstractCatalogServiceTest<KvCatalogServiceImpl> {

	public KvCatalogServiceImplIT(@Autowired KvCatalogServiceImpl catalogService) {
		super(catalogService);
		this.testGetSongListStylesEnabled = false;
		this.testGetSongListThemeEnabled = false;
		this.testGetSongListTopEnabled = false;
		this.testGetSongListNewsEnabled = false;
		this.testGetSelectionEnabled = false;
		this.testGetSelectionListEnabled = false;
	}

}
