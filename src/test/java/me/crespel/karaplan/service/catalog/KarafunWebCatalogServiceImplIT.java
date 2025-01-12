package me.crespel.karaplan.service.catalog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
public class KarafunWebCatalogServiceImplIT extends AbstractCatalogServiceTest<KarafunWebCatalogServiceImpl> {

	public KarafunWebCatalogServiceImplIT(@Autowired KarafunWebCatalogServiceImpl catalogService) {
		super(catalogService);
		this.testGetArtistEnabled = false;
		this.testGetSongFileListEnabled = false;
	}

}
