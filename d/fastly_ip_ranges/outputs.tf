output "cidr_blocks" {
  description = "returns a list of string"
  value       = data.fastly_ip_ranges.this.cidr_blocks
}

output "id" {
  description = "returns a string"
  value       = data.fastly_ip_ranges.this.id
}

output "ipv6_cidr_blocks" {
  description = "returns a list of string"
  value       = data.fastly_ip_ranges.this.ipv6_cidr_blocks
}

output "this" {
  value = fastly_ip_ranges.this
}

