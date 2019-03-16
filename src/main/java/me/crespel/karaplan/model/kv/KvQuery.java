package me.crespel.karaplan.model.kv;

import java.util.List;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
public class KvQuery<T> {

	private Integer affiliateId;
	private String function;
	private T parameters;

	@Data
	@Accessors(chain = true)
	public static class ArtistGet {
		private Long id;
	}

	@Data
	@Accessors(chain = true)
	public static class ArtistList {
		private List<Long> id;
		private Integer limit;
		private Long offset;
	}

	@Data
	@Accessors(chain = true)
	public static class SongGet {
		private Long id;
	}

	@Data
	@Accessors(chain = true)
	public static class SongList {
		private List<Long> id;
		private List<Long> artistId;
		private Integer limit;
		private Long offset;
	}

	@Data
	@Accessors(chain = true)
	public static class SearchSong {
		private String query;
		private Integer limit;
		private Long offset;
	}

}
