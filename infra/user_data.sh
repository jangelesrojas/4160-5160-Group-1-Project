#!/bin/bash
set -e

# install docker
dnf update -y
dnf install -y docker
systemctl enable docker
systemctl start docker

# install aws cli v2 (already present on AL2023, but ensure login command exists)
if ! command -v aws &> /dev/null; then
  dnf install -y awscli
fi

# login to ecr and pull the latest image that CI will push
aws ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${repo_url}
docker pull ${repo_url}:latest || true

# stop previous container if exists
docker rm -f misconfig-api || true

# run container mapping 80 -> 8000
docker run -d --name misconfig-api \
  -p 80:8000 \
  -e OPENAI_API_KEY='${openai_api_key}' \
  -e USE_BOTO=0 \
  ${repo_url}:latest
