# Broker Example

> This is a clone of the SPIRE quickstart tutorial: https://github.com/spiffe/spire-tutorials/tree/main/k8s/quickstart.

## Steps

* Run a local Kubernetes cluster
* Run `test.sh` - which applies kustomize template and registers SPIRE server entries.
* Run either of the following to retrieve an identity via a broker. (also try replacing `app=workload-a` with `app=workload-b`)

```
kubectl exec $(kubectl get pods -l "app=workload-a" -o name) -- \
    grpcurl -plaintext \
        -d '{"audience":"test"}'\
        -H workload.spiffe.io:true \
        localhost:8080 \
        SpiffeWorkloadAPI/FetchJWTSVID
```

```
kubectl exec $(kubectl get pods -l "app=workload-a" -o name) -- \
    grpcurl -plaintext \
        -d '{"audience":"test"}'\
        -H workload.spiffe.io:true \
        --unix /run/spire/sockets/broker.sock \
        SpiffeWorkloadAPI/FetchJWTSVID
```