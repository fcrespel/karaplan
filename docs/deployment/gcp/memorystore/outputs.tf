output "redis_host" {
  value       = google_redis_instance.karaplan-redis.host
  description = "Redis host"
}
output "redis_port" {
  value       = google_redis_instance.karaplan-redis.port
  description = "Redis port"
}
