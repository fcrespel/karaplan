package me.crespel.karaplan;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import me.crespel.karaplan.service.CatalogService;

@RunWith(SpringRunner.class)
@SpringBootTest
public class KaraplanApplicationTests {

	@Autowired
	protected CatalogService catalog;

	@Test
	public void contextLoads() {
	}

}
