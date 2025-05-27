# OSU Benchmarks

Here is an example of running OSU benchmarks with GPU. The [base image](https://github.com/converged-computing/performance-study/blob/main/docker/google/gpu/osu/Dockerfile) was intended for NVIDIA V100 (CUDA 12.4.1) and may need a rebuild for newer drivers. We assume you already have a cluster, and ideally you are running in single threaded mode (The Google Cloud flag to create the cluster is `--threads-per-core=1`), so the number of tasks below is talking about actual physical CPU. We also assume you've cloned and are working from this repository with the `osu-benchmarks` helm chart. Install the Flux Operator: 

```bash
kubectl apply -f https://raw.githubusercontent.com/flux-framework/flux-operator/refs/heads/main/examples/dist/flux-operator.yaml
```

You can check logs in the `operator-namespace` and make sure it is running. Make a directory to pipe logs into.

```bash
mkdir -p ./logs
```

## Pair to Pair Benchmarks

In "pairs" mode we run for 28 combinations, 8 nodes 2 at a time.  The number of tasks and pairs below doesn't need to change - just the number of nodes. It has a loop to loop over benchmarks (and you can add/remove pair to pairs you want) but I generally test the first one manually to make sure it looks OK. For a new setup the biggest issue you might run into is with respect to your OSU container build.

```bash
helm dependency update osu-benchmarks
for app in osu_latency osu_bw
  do
  helm install \
  --set experiment.nodes=NODES \
  --set experiment.tasks=2 \
  --set experiment.pairs=8 \
  --set experiment.gpu_affinity=per-task \
  --set minicluster.size=NODES \
  --set minicluster.gpus=8 \
  --set minicluster.tasks=2 \
  --set minicluster.save_logs=true \
  --set minicluster.image=ghcr.io/converged-computing/metric-osu-gpu:latest \
  --set osu.binary=/opt/osu-benchmark/build.openmpi/mpi/pt2pt/$app \
  --set osu.device_to_device=true \
  osu osu-benchmarks/
  sleep 5
  time kubectl wait --for=condition=ready pod -l job-name=osu --timeout=600s
  pod=$(kubectl get pods -o json | jq  -r .items[0].metadata.name)
  kubectl logs ${pod} -f |& tee ./logs/$app.out
  helm uninstall osu
done
```

And AllReduce

```bash
helm install \
  --set experiment.nodes=NODES \
  --set minicluster.size=NODES \
  --set minicluster.tasks=TASKS \
  --set experiment.tasks=TASKS \
  --set experiment.iterations=5 \
  --set experiment.gpu_affinity=per-task \
  --set minicluster.gpus=8 \
  --set minicluster.save_logs=true \
  --set minicluster.image=ghcr.io/converged-computing/metric-osu-gpu:latest \
  --set osu.binary=/opt/osu-benchmark/build.openmpi/mpi/collective/osu_allreduce \
  --set osu.device_to_device=true \
  osu osu-benchmarks/ 

time kubectl wait --for=condition=ready pod -l job-name=osu --timeout=600s
pod=$(kubectl get pods -o json | jq  -r .items[0].metadata.name)
kubectl logs ${pod} -f |& tee ./logs/osu_allreduce.out
helm uninstall osu
```

## Notes

### Docker Build

I've only tested this on (what are considered) older GPU, so likely you'll need a new container build. The previous one we used on Google Cloud is this [base image](https://github.com/converged-computing/performance-study/blob/main/docker/google/gpu/osu/Dockerfile). However let me know if I can help to build. This design has Flux in the container instead of having the operator add it on the fly.

### Environment

If you need to add environment variables for your setup you can do `--set env.NAME=VALUE`. Note that `CUDA_VISIBLE_DEVICES` is added automatically based on the number of GPU. The above is also setup to do device to device mode `osu_allreduce -d cuda H H`. For host to host mode instead set `--set osu.host_to_host=true`. To change the image to one you've built, use `--set minicluster.image=<your-image>`.

### Interactive Mode

If you need to debug, do `--set minicluster.interactive=true` and glance at the log to see commands to try. Then shell into the rank 0 pod, and you can activate the view:

```bash
flux proxy local:///mnt/flux/view/run/flux/local bash
flux resource list
```

Then test the commands you saw in the logs (or do your own testing). For the chart debugging, add `--dry-run`. If needed, a simple version of the Flux Operator CRD can be seen [here](https://github.com/converged-computing/performance-study/blob/main/experiments/google/gke/gpu/crd/osu.yaml), but you need to shell in, connect to the lead broker, and orchestrate the experiment and save logs, etc.
