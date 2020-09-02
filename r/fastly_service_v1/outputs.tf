output "active_version" {
  description = "returns a number"
  value       = fastly_service_v1.this.active_version
}

output "cloned_version" {
  description = "returns a number"
  value       = fastly_service_v1.this.cloned_version
}

output "default_host" {
  description = "returns a string"
  value       = fastly_service_v1.this.default_host
}

output "id" {
  description = "returns a string"
  value       = fastly_service_v1.this.id
}

output "this" {
  value = fastly_service_v1.this
}

