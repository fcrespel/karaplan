package me.crespel.karaplan.service.catalog;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
public class RecisioCatalogServiceImplIT extends AbstractCatalogServiceTest<RecisioCatalogServiceImpl> {

	public RecisioCatalogServiceImplIT(@Autowired RecisioCatalogServiceImpl catalogService) {
		super(catalogService);
	}

}
