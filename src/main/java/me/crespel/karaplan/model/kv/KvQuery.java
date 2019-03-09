package me.crespel.karaplan.model.kv;

import java.util.Map;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
public class KvQuery {

	private Integer affiliateId;
	private String function;
	private Map<String, Object> parameters;

}
