output "active_version" {
  description = "returns a number"
  value       = fastly_service_compute.this.active_version
}

output "cloned_version" {
  description = "returns a number"
  value       = fastly_service_compute.this.cloned_version
}

output "id" {
  description = "returns a string"
  value       = fastly_service_compute.this.id
}

output "this" {
  value = fastly_service_compute.this
}

