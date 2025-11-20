# ECR repo to hold the image that GitHub Actions will push
resource "aws_ecr_repository" "repo" {
  name = var.project_name
  image_scanning_configuration { scan_on_push = true }
}

# IAM role for EC2 so it can pull from ECR and receive SSM commands
resource "aws_iam_role" "ec2_role" {
  name               = "${var.project_name}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Attach basic policies: SSM and ECR read
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy_attachment" "ecr_read" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-profile"
  role = aws_iam_role.ec2_role.name
}

# Security group: SSH 22 from your IP, HTTP 80 from anywhere
# You can tighten later; for demo this is fine
data "http" "myip" { url = "https://checkip.amazonaws.com" }
locals {
  my_cidr = "${chomp(data.http.myip.response_body)}/32"
}

resource "aws_security_group" "web" {
  name        = "${var.project_name}-sg"
  description = "Allow SSH and HTTP"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.my_cidr]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_vpc" "default" { default = true }

# Look up subnets in the default VPC
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}


# EC2 user data installs docker, logs in to ECR, pulls latest image, and runs container on port 80
data "template_file" "ud" {
  template = file("${path.module}/user_data.sh")
  vars = {
    region         = var.region
    repo_url       = aws_ecr_repository.repo.repository_url
    openai_api_key = var.openai_api_key
  }
}

resource "aws_instance" "app" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  user_data                   = data.template_file.ud.rendered
  associate_public_ip_address = true
  tags                        = { Name = "${var.project_name}-ec2" }
}

# Latest Amazon Linux 2023 AMI
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}
