package me.crespel.karaplan.service.song;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.ConfigurableConversionService;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Sets;

import me.crespel.karaplan.domain.Song;
import me.crespel.karaplan.domain.SongComment;
import me.crespel.karaplan.domain.SongVote;
import me.crespel.karaplan.domain.Style;
import me.crespel.karaplan.domain.User;
import me.crespel.karaplan.model.CatalogSong;
import me.crespel.karaplan.model.CatalogSongList;
import me.crespel.karaplan.model.CatalogSongListType;
import me.crespel.karaplan.model.CatalogStyle;
import me.crespel.karaplan.repository.SongCommentRepo;
import me.crespel.karaplan.repository.SongRepo;
import me.crespel.karaplan.repository.SongVoteRepo;
import me.crespel.karaplan.service.ArtistService;
import me.crespel.karaplan.service.CatalogService;
import me.crespel.karaplan.service.SongService;

@Service
public class SongServiceImpl implements SongService {

	private final SongRepo songRepo;
	private final SongVoteRepo songVoteRepo;
	private final SongCommentRepo songCommentRepo;
	private final CatalogService catalogService;
	private final ArtistService artistService;
	private final ConfigurableConversionService conversionService;

	public SongServiceImpl(SongRepo songRepo, SongVoteRepo songVoteRepo, SongCommentRepo songCommentRepo, CatalogService catalogService, ArtistService artistService) {
		this.songRepo = songRepo;
		this.songVoteRepo = songVoteRepo;
		this.songCommentRepo = songCommentRepo;
		this.catalogService = catalogService;
		this.artistService = artistService;
		this.conversionService = new DefaultConversionService();
		this.conversionService.addConverter(new CatalogSongToSongConverter());
		this.conversionService.addConverter(new CatalogStyleToStyleConverter());
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Song> findAll() {
		return Sets.newLinkedHashSet(songRepo.findAll());
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Song> findAll(Pageable pageable) {
		return Sets.newLinkedHashSet(songRepo.findAll(pageable));
	}

	@Override
	public Set<Song> findAllByUserId(Long userId, Pageable pageable) {
		return Sets.newLinkedHashSet(songRepo.findAllByVotesUserId(userId, pageable));
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Song> findById(Long id) {
		return songRepo.findById(id);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Song> findByCatalogId(Long catalogId) {
		return findByCatalogId(catalogId, null);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<Song> findByCatalogId(Long catalogId, Locale locale) {
		Optional<Song> localSong = songRepo.findByCatalogId(catalogId);
		Optional<Song> catalogSong = Optional.ofNullable(conversionService.convert(catalogService.getSong(catalogId, locale), Song.class));
		return mergeSongs(localSong, catalogSong);
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Song> search(CatalogSongListType type, String query, Pageable pageable) {
		return search(type, query, pageable, null);
	}

	@Override
	@Transactional(readOnly = true)
	public Set<Song> search(CatalogSongListType type, String query, Pageable pageable, Locale locale) {
		Set<Song> resultSongs = Sets.newLinkedHashSet();

		CatalogSongList catalogSongList = catalogService.getSongList(type, query, pageable.getPageSize(), pageable.getOffset(), locale);
		if (catalogSongList.getSongs() != null) {
			// Convert catalog songs
			Set<Song> catalogSongs = catalogSongList.getSongs().stream()
					.map(it -> conversionService.convert(it, Song.class))
					.collect(Collectors.toCollection(LinkedHashSet::new));

			// Find all catalog IDs
			Set<Long> catalogSongIds = catalogSongs.stream()
					.map(Song::getCatalogId)
					.collect(Collectors.toCollection(LinkedHashSet::new));

			// Find all matching local songs
			Set<Song> localSongs = Sets.newLinkedHashSet(songRepo.findAllByCatalogIdIn(catalogSongIds));

			// Merge results
			resultSongs.addAll(Stream.of(catalogSongs, localSongs)
					.flatMap(Collection::stream)
					.collect(Collectors.toMap(Song::getCatalogId, Function.identity(), (catalog, local) -> mergeSongs(Optional.of(local), Optional.of(catalog)).get(), LinkedHashMap::new))
					.values());
		}
		return resultSongs;
	}

	@Override
	@Transactional
	public Song save(Song song) {
		song.updateStats();
		return songRepo.save(song);
	}

	@Override
	@Transactional
	public Song vote(Song song, User user, int score) {
		if (song.getId() == null) {
			song = songRepo.save(song);
		}

		SongVote songVote = songVoteRepo.findBySongAndUser(song, user).orElseGet(SongVote::new).setSong(song).setUser(user);
		if (songVote.getId() != null) {
			song.getVotes().remove(songVote);
		}
		if (score != 0) {
			songVote.setScore(score > 0 ? 1 : -1);
			song.getVotes().add(songVote);
		}
		return save(song);
	}

	@Override
	@Transactional
	public void removeUserVotes(User user) {
		Iterable<SongVote> songVotes = songVoteRepo.findAllByUser(user);
		for (SongVote songVote : songVotes) {
			Song song = songVote.getSong();
			song.getVotes().remove(songVote);
			save(song);
		}
	}

	@Override
	@Transactional
	public Song addComment(Song song, User user, String comment) {
		if (song.getId() == null) {
			song = songRepo.save(song);
		}

		song.getComments().add(new SongComment()
				.setSong(song)
				.setUser(user)
				.setComment(comment));
		return save(song);
	}

	@Override
	@Transactional
	public Song removeComment(Song song, long commentId) {
		return removeComment(song, null, commentId);
	}

	@Override
	@Transactional
	public Song removeComment(Song song, User user, long commentId) {
		song.getComments().removeIf(it -> it.getId() == commentId && (user == null || user.equals(it.getUser())));
		return save(song);
	}

	@Override
	@Transactional
	public void removeUserComments(User user) {
		Iterable<SongComment> songComments = songCommentRepo.findAllByUser(user);
		for (SongComment songComment : songComments) {
			Song song = songComment.getSong();
			song.getComments().remove(songComment);
			save(song);
		}
	}

	private Optional<Song> mergeSongs(Optional<Song> song1, Optional<Song> song2) {
		if (song1.isPresent()) {
			if (song2.isPresent()) {
				Song s1 = song1.get();
				Song s2 = song2.get();
				if (s1.getCatalogId() == null)
					s1.setCatalogId(s2.getCatalogId());
				if (s1.getName() == null)
					s1.setName(s2.getName());
				if (s1.getDuration() == null)
					s1.setDuration(s2.getDuration());
				if (s1.getYear() == null)
					s1.setYear(s2.getYear());
				if (s1.getImage() == null)
					s1.setImage(s2.getImage());
				if (s1.getRights() == null)
					s1.setRights(s2.getRights());
				if (s1.getArtist() == null)
					s1.setArtist(s2.getArtist());
				if (s1.getStyles() == null || s1.getStyles().isEmpty())
					s1.setStyles(s2.getStyles());
				return song1;
			} else {
				return song1;
			}
		} else if (song2.isPresent()) {
			return song2;
		} else {
			return Optional.empty();
		}
	}

	public class CatalogSongToSongConverter implements Converter<CatalogSong, Song> {

		@Override
		public Song convert(CatalogSong source) {
			Song song = new Song()
					.setCatalogId(source.getId())
					.setName(source.getName())
					.setDuration(source.getDuration())
					.setYear(source.getYear())
					.setImage(source.getImg())
					.setRights(source.getRights())
					.setArtist(artistService.findByCatalogId(source.getArtist().getId()).orElse(null));
			if (source.getStyles() != null) {
				song.setStyles(source.getStyles().stream()
						.map(it -> conversionService.convert(it, Style.class))
						.collect(Collectors.toCollection(LinkedHashSet::new)));
			}
			return song;
		}

	}

	public class CatalogStyleToStyleConverter implements Converter<CatalogStyle, Style> {

		@Override
		public Style convert(CatalogStyle source) {
			return new Style()
					.setCatalogId(source.getId())
					.setName(source.getName())
					.setImage(source.getImg());
		}

	}

}
