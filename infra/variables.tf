variable "project_name" {
  type    = string
  default = "4160-5160-group-1-project"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "openai_api_key" {
  type    = string
  default = "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"
}

variable "aws_access_key" {
  type = string
}

variable "aws_secret_key" {
  type = string
}
