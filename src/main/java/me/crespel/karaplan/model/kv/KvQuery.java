package me.crespel.karaplan.model.kv;

import java.util.Map;

import lombok.Data;

@Data
public class KvQuery {

	private Integer affiliateId;
	private String function;
	private Map<String, Object> parameters;

}
