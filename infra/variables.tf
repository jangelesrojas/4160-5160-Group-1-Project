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
  default = ""
}

variable "aws_access_key" {
  type = string
}

variable "aws_secret_key" {
  type = string
}
