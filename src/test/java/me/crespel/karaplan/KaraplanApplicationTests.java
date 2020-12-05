package me.crespel.karaplan;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import me.crespel.karaplan.service.CatalogService;

@SpringBootTest
@ActiveProfiles("test")
public class KaraplanApplicationTests {

	@Autowired
	protected CatalogService catalog;

	@Test
	public void contextLoads() {
	}

}
