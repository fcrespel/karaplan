package me.crespel.karaplan.service.catalog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.util.Locale;

import org.junit.jupiter.api.Test;

import me.crespel.karaplan.model.CatalogArtist;
import me.crespel.karaplan.model.CatalogSelection;
import me.crespel.karaplan.model.CatalogSelectionList;
import me.crespel.karaplan.model.CatalogSelectionType;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongFileList;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.service.CatalogService;

public abstract class AbstractCatalogServiceTest<T extends CatalogService> {

	protected static final Locale DEFAULT_LOCALE = Locale.ENGLISH;
	protected static final int LIST_LIMIT = 10;
	protected static final long LIST_OFFSET = 0;
	protected static final long SONG_ID = 19237;
	protected static final String SONG_NAME = "Feeling Good";
	protected static final long ARTIST_ID = 3888;
	protected static final String ARTIST_NAME = "Muse";
	protected static final long STYLE_ID = 2;  // Rock
	protected static final long THEME_ID = 94; // Best Of
	protected static final long TOP_ID = 100;  // Global Top
	protected static final long NEWS_ID = 123; // Top Hits

	protected T catalogService;
	protected Locale locale;
	protected boolean testGetArtistEnabled = true;
	protected boolean testGetSongEnabled = true;
	protected boolean testGetSongListEnabled = true;
	protected boolean testGetSongListQueryEnabled = true;
	protected boolean testGetSongListArtistEnabled = true;
	protected boolean testGetSongListStylesEnabled = true;
	protected boolean testGetSongListThemeEnabled = true;
	protected boolean testGetSongListTopEnabled = true;
	protected boolean testGetSongListNewsEnabled = true;
	protected boolean testGetSongFileListEnabled = true;
	protected boolean testGetSelectionEnabled = true;
	protected boolean testGetSelectionStylesEnabled = true;
	protected boolean testGetSelectionThemeEnabled = true;
	protected boolean testGetSelectionTopEnabled = true;
	protected boolean testGetSelectionNewsEnabled = true;
	protected boolean testGetSelectionListEnabled = true;
	protected boolean testGetSelectionListStylesEnabled = true;
	protected boolean testGetSelectionListThemeEnabled = true;
	protected boolean testGetSelectionListTopEnabled = true;
	protected boolean testGetSelectionListNewsEnabled = true;

	public AbstractCatalogServiceTest(T catalogService) {
		this(catalogService, DEFAULT_LOCALE);
	}

	public AbstractCatalogServiceTest(T catalogService, Locale locale) {
		this.catalogService = catalogService;
		this.locale = locale;
	}

	@Test
	public void testGetArtist() {
		assumeThat(testGetArtistEnabled).isTrue();
		CatalogArtist artist = catalogService.getArtist(ARTIST_ID);
		assertThat(artist).isNotNull();
		assertThat(artist.getId()).isEqualTo(ARTIST_ID);
		assertThat(artist.getName()).isEqualTo(ARTIST_NAME);
	}

	@Test
	public void testGetSong() {
		assumeThat(testGetSongEnabled).isTrue();
		CatalogSong song = catalogService.getSong(SONG_ID, locale);
		assertThat(song).isNotNull();
		assertThat(song.getId()).isEqualTo(SONG_ID);
		assertThat(song.getName()).isEqualTo(SONG_NAME);
		assertThat(song.getArtist()).isNotNull();
		assertThat(song.getArtist().getId()).isEqualTo(ARTIST_ID);
	}

	@Test
	public void testGetSongListQuery() {
		assumeThat(testGetSongListEnabled && testGetSongListQueryEnabled).isTrue();
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.query, ARTIST_NAME, LIST_LIMIT, LIST_OFFSET, locale);
		assertThat(list).isNotNull();
		assertThat(list.getCount()).isPositive();
		assertThat(list.getSongs()).isNotEmpty();
	}

	@Test
	public void testGetSongListArtist() {
		assumeThat(testGetSongListEnabled && testGetSongListArtistEnabled).isTrue();
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.artist, String.valueOf(ARTIST_ID), LIST_LIMIT, LIST_OFFSET, locale);
		assertThat(list).isNotNull();
		assertThat(list.getCount()).isPositive();
		assertThat(list.getSongs()).isNotEmpty();
	}

	@Test
	public void testGetSongListStyles() {
		assumeThat(testGetSongListEnabled && testGetSongListStylesEnabled).isTrue();
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.styles, String.valueOf(STYLE_ID), LIST_LIMIT, LIST_OFFSET, locale);
		assertThat(list).isNotNull();
		assertThat(list.getCount()).isPositive();
		assertThat(list.getSongs()).isNotEmpty();
	}

	@Test
	public void testGetSongListTheme() {
		assumeThat(testGetSongListEnabled && testGetSongListThemeEnabled).isTrue();
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.theme, String.valueOf(THEME_ID), LIST_LIMIT, LIST_OFFSET, locale);
		assertThat(list).isNotNull();
		assertThat(list.getCount()).isPositive();
		assertThat(list.getSongs()).isNotEmpty();
	}

	@Test
	public void testGetSongListTop() {
		assumeThat(testGetSongListEnabled && testGetSongListTopEnabled).isTrue();
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.top, String.valueOf(TOP_ID), LIST_LIMIT, LIST_OFFSET, locale);
		assertThat(list).isNotNull();
		assertThat(list.getCount()).isPositive();
		assertThat(list.getSongs()).isNotEmpty();
	}

	@Test
	public void testGetSongListNews() {
		assumeThat(testGetSongListEnabled && testGetSongListNewsEnabled).isTrue();
		CatalogSongList list = catalogService.getSongList(CatalogSongListType.news, String.valueOf(NEWS_ID), LIST_LIMIT, LIST_OFFSET, locale);
		assertThat(list).isNotNull();
		assertThat(list.getCount()).isPositive();
		assertThat(list.getSongs()).isNotEmpty();
	}

	@Test
	public void testGetSongFileList() {
		assumeThat(testGetSongFileListEnabled).isTrue();
		CatalogSongFileList list = catalogService.getSongFileList(SONG_ID, locale);
		assertThat(list).isNotNull();
		assertThat(list.getLength()).isPositive();
		assertThat(list.getSongFiles()).isNotEmpty();
	}

	@Test
	public void testGetSelectionStyles() {
		assumeThat(testGetSelectionEnabled && testGetSelectionStylesEnabled).isTrue();
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.styles, STYLE_ID, locale);
		assertThat(selection).isNotNull();
		assertThat(selection.getId()).isEqualTo(STYLE_ID);
		assertThat(selection.getName()).isNotEmpty();
	}

	@Test
	public void testGetSelectionTheme() {
		assumeThat(testGetSelectionEnabled && testGetSelectionThemeEnabled).isTrue();
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.theme, THEME_ID, locale);
		assertThat(selection).isNotNull();
		assertThat(selection.getId()).isEqualTo(THEME_ID);
		assertThat(selection.getName()).isNotEmpty();
	}

	@Test
	public void testGetSelectionTop() {
		assumeThat(testGetSelectionEnabled && testGetSelectionTopEnabled).isTrue();
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.top, TOP_ID, locale);
		assertThat(selection).isNotNull();
		assertThat(selection.getId()).isEqualTo(TOP_ID);
		assertThat(selection.getName()).isNotEmpty();
	}

	@Test
	public void testGetSelectionNews() {
		assumeThat(testGetSelectionEnabled && testGetSelectionNewsEnabled).isTrue();
		CatalogSelection selection = catalogService.getSelection(CatalogSelectionType.news, NEWS_ID, locale);
		assertThat(selection).isNotNull();
		assertThat(selection.getId()).isEqualTo(NEWS_ID);
		assertThat(selection.getName()).isNotEmpty();
	}

	@Test
	public void testGetSelectionListStyles() {
		assumeThat(testGetSelectionListEnabled && testGetSelectionListStylesEnabled).isTrue();
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.styles, locale);
		assertThat(list).isNotNull();
		assertThat(list.getType()).isEqualTo(CatalogSelectionType.styles);
		assertThat(list.getSelections()).isNotEmpty();
	}

	@Test
	public void testGetSelectionListTheme() {
		assumeThat(testGetSelectionListEnabled && testGetSelectionListThemeEnabled).isTrue();
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.theme, locale);
		assertThat(list).isNotNull();
		assertThat(list.getType()).isEqualTo(CatalogSelectionType.theme);
		assertThat(list.getSelections()).isNotEmpty();
	}

	@Test
	public void testGetSelectionListTop() {
		assumeThat(testGetSelectionListEnabled && testGetSelectionListTopEnabled).isTrue();
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.top, locale);
		assertThat(list).isNotNull();
		assertThat(list.getType()).isEqualTo(CatalogSelectionType.top);
		assertThat(list.getSelections()).isNotEmpty();
	}

	@Test
	public void testGetSelectionListNews() {
		assumeThat(testGetSelectionListEnabled && testGetSelectionListNewsEnabled).isTrue();
		CatalogSelectionList list = catalogService.getSelectionList(CatalogSelectionType.news, locale);
		assertThat(list).isNotNull();
		assertThat(list.getType()).isEqualTo(CatalogSelectionType.news);
		assertThat(list.getSelections()).isNotEmpty();
	}

}
