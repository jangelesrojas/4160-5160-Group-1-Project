variable "project_name" {
  type    = string
  default = "4160-5160-Group-1-Project"
}
variable "region"       { type = string  default = "us-east-1" }
variable "instance_type"{ type = string  default = "t3.micro" }
variable "openai_api_key" { type = string  default = "" } # optional demo works partially without a key
