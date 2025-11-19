output "ecr_repository_url" { value = aws_ecr_repository.repo.repository_url }
output "ec2_public_ip"     { value = aws_instance.app.public_ip }
output "security_group_id" { value = aws_security_group.web.id }
