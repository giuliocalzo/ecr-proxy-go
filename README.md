# ecr-proxy

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/ecr-proxy)](https://artifacthub.io/packages/search?repo=ecr-proxy)

## Overview

**ecr-proxy** is a lightweight proxy service that enables seamless access to AWS ECR (Elastic Container Registry) images from environments where direct ECR access is restricted or inconvenient.

## Features

- Simple deployment as a container or binary
- Supports authentication with AWS ECR
- Transparent proxying of Docker image pulls and pushes
- Minimal configuration required

## Usage

1. Deploy `ecr-proxy` in your environment (e.g., Kubernetes, Docker).
2. Configure your Docker client or CI/CD pipeline to use the proxy as the registry endpoint.
3. Pull or push images as you would with any Docker registry.

## Example

```sh
docker run -d \
    -e AWS_ACCESS_KEY_ID=your-access-key \
    -e AWS_SECRET_ACCESS_KEY=your-secret-key \
    -e AWS_ACCOUNT_ID=1234567890 \
    -e AWS_REGION=us-west-1 \
    -p 5000:5000 \
    ghcr.io/giuliocalzo/ecr-proxy-go:latest
```

## Kube Deployment

Use [AWS IRSA](https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html) with the following permission

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:BatchGetImage",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
```

install everything with

```
helm upgrade --install ecr-proxy oci://ghcr.io/giuliocalzo/ecr-proxy -n ecr-proxy --create-namespace --debug -f chart/values-example.yaml
```

for extra info on helm values [read here](chart/README.md)

## License

[WTFPL](LICENSE)
