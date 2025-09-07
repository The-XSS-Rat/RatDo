# Deployment Guide

## Docker Image

1. Build the image:
   ```sh
   docker build -t your-docker-repo/ratdo:latest .
   ```
2. Push the image:
   ```sh
   docker push your-docker-repo/ratdo:latest
   ```

## Kubernetes

1. Save your kubeconfig from the prompt into `kubeconfig.yaml`.
2. Deploy to the cluster:
   ```sh
   kubectl --kubeconfig kubeconfig.yaml apply -f k8s/deployment.yaml
   ```
3. Check service status:
   ```sh
   kubectl --kubeconfig kubeconfig.yaml get svc ratdo
   ```
