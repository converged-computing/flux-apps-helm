# Flux Operator Apps

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.15665233.svg)](https://doi.org/10.5281/zenodo.15665233)

These are simple helm charts to run HPC applications in Kubernetes using the Flux Operator. You can customize each different application to your needs, from the container, to size, to iterations, etc. We have a simple strategy that uses:

 - [base-template](base-template): A base template MiniCluster that is used acrossed apps.
 - Applications: are each included in a subdirectory here. Usage is consistent across applications, with the exception of the application specific parameters. For each application, those are included in the respective READMEs.

## Overview

Each application can be customized for anything related to the MiniCluster (e.g., size, flux view, logging, TBA resources), and anything related to the application itself (parameters, containers, etc). Given the use of a common template, the actual definition of the application is fairly small (and thus they are easy to write). This is a nice approach because:

- We don't require extra software installed into the MiniCluster
- An application definition is simple (and can be written easily / quickly)
- Changing logic for the MiniCluster only needs to be done in one place!
- Applications can be programatically built and tested (when possible)
- Experiments can be orchestrated via using these helm charts with a custom values.yaml for each application (see our example runs [in the Google Performance Study](https://github.com/converged-computing/google-performance-study/tree/main/experiments/gke/cpu/size-128)).

## Variables

The following variables are available for every experiment, and already part of the template.  Variables with a default will have the default set, otherwise the flag (or similar) is usually left out.

| Name  | Description | Default | Options |
|-------|-------------|---------|---------|
| nodes | Number of nodes `-N` for each job | 1 | |
| tasks | Number of tasks `-n` for each job | unset | |
| cpu_affinity | Set `--cpu-affinity` | `per-task` | `(off,per-task,map:LIST,on)` | 
| gpu_affinity | Set `--gpu-affinity` | `off` | `(off,per-task,map:LIST,on)` |
| run_threads | sets `OMP_NUM_THREADS` | unset | |
| cores_per_task | Set `--cores-per-task` | unset | |
| exclusive | Add the `--exclusive` flag | unset | |

You define them via `--set experiment.<name>=<value>` or in a values.yaml to create the experiment from:

```yaml
experiment:
  nodes: 5
```

Experiment specific variables are defined in the values.yaml files associated with the experiment.

## Usage

This example will walk through running lammps. Other example runs are [also provided below](#examples).

### 1. Setup the Cluster

For simple local development:

```bash
# Create the cluster
kind create cluster --config ./kind-config.yaml
```

For ebpf (that requires mounting the host) I recommend a cloud:

```bash
NODES=1
GOOGLE_PROJECT=llnl-flux
INSTANCE=h3-standard-88
ctime gcloud container clusters create test-cluster  --threads-per-core=1  --num-nodes=$NODES --machine-type=$INSTANCE  --placement-type=COMPACT --image-type=UBUNTU_CONTAINERD --region=us-central1-a --project=${GOOGLE_PROJECT}

# When time to delete
gcloud container clusters delete test-cluster --region=us-central1-a
```

Finally, install the Flux Operator

```bash
kubectl apply -f https://raw.githubusercontent.com/flux-framework/flux-operator/refs/heads/main/examples/dist/flux-operator.yaml
```

### 2. View Values

Here are the values we can customize (any can be exposed really, it's very simple).

```bash
helm show values ./lammps-reax
```
```console
# Default values for lammps experiment
# This is a YAML-formatted file.
# Declare variables to be passed into your templates.

# Logging (quiet will hide flux setup)
logging:
  quiet: true

experiment:
  iterations: 1
  nodes: 1
  tasks: 2

env:
  app: lammps

lammps:
  binary: /usr/bin/lmp
  input: in.reaxff.hns
  x: 2
  y: 2
  z: 2
  
flux:
  image: ghcr.io/converged-computing/flux-view-ubuntu:tag-jammy

minicluster:
  # Container image
  image: "ghcr.io/converged-computing/lammps-reax:ubuntu2204"

  # Interactive MiniCluster?
  interactive: false
  
  # MiniCluster size
  size: 1
  
  # Number of NVIDIA gpus
  gpus: 0

  # Add flux on the fly (set to false if Flux is already in the container)
  addFlux: false
```

If there are changes to the base template:

```bash
helm dependency update lammps-reax/
helm install lammps lammps-reax/ --debug --dry-run
```

### 3. Install LAMMPS Chart

Then install the chart. This will deploy the Flux MiniCluster and run lammps for some number of iterations. All variables are technically defined so you don't need any `--set`.

```bash
container=$(ocifit ghcr.io/converged-computing/lammps-reax --instance)
helm install \
  --set minicluster.size=1 \
  --set minicluster.image= \
  --set minicluster.addFlux=true \
  lammps ./lammps-reax
```
```console
NAME: lammps
LAST DEPLOYED: Sun May 11 13:10:50 2025
NAMESPACE: default
STATUS: deployed
REVISION: 1
TEST SUITE: None
```

Or just look at [the chart](./lammps-reax/values.yaml)

If you want to debug or otherwise print to the console:

```bash
helm template --debug \
  --set minicluster.size=4 \
  --set minicluster.image=ghcr.io/converged-computing/metric-lammps-cpu:zen4-reax \
  ./lammps-reax
```

### 4. View Output

The output can be seen in the lead broker pod!

```bash
kubectl logs lammps-0-xxxx -f
```

<details>

<summary> LAMMPS output </summary>

```console
Defaulted container "lammps" out of: lammps, flux-view (init)
#!/bin/bash
set -euo pipefail
mkdir -p /tmp/output
flux resource list

for i in {1..1}
do
  echo "FLUX-RUN START lammps-iter-$i"
  flux run --setattr=user.study_id=lammps-iter-$i -N1 -n 2 -o cpu-affinity=per-task -o gpu-affinity=off      /usr/bin/lmp -v x 2 -v y 2 -v z 2 -in in.reaxff.hns -nocite |& tee /tmp/lammps.out
  
   echo "FLUX-RUN END lammps-iter-$i"
done


     STATE NNODES   NCORES    NGPUS NODELIST
      free      1        8        0 lammps-0
 allocated      0        0        0 
      down      0        0        0 
FLUX-RUN START lammps-iter-1
LAMMPS (17 Apr 2024 - Development - a8687b5)
OMP_NUM_THREADS environment is not set. Defaulting to 1 thread. (src/comm.cpp:98)
  using 1 OpenMP thread(s) per MPI task
Reading data file ...
  triclinic box = (0 0 0) to (22.326 11.1412 13.778966) with tilt (0 -5.02603 0)
  2 by 1 by 1 MPI processor grid
  reading atoms ...
  304 atoms
  reading velocities ...
  304 velocities
  read_data CPU = 0.001 seconds
Replication is creating a 2x2x2 = 8 times larger system...
  triclinic box = (0 0 0) to (44.652 22.2824 27.557932) with tilt (0 -10.05206 0)
  2 by 1 by 1 MPI processor grid
  bounding box image = (0 -1 -1) to (0 1 1)
  bounding box extra memory = 0.03 MB
  average # of replicas added to proc = 5.00 out of 8 (62.50%)
  2432 atoms
  replicate CPU = 0.000 seconds
Neighbor list info ...
  update: every = 20 steps, delay = 0 steps, check = no
  max neighbors/atom: 2000, page size: 100000
  master list distance cutoff = 11
  ghost atom cutoff = 11
  binsize = 5.5, bins = 10 5 6
  2 neighbor lists, perpetual/occasional/extra = 2 0 0
  (1) pair reaxff, perpetual
      attributes: half, newton off, ghost
      pair build: half/bin/ghost/newtoff
      stencil: full/ghost/bin/3d
      bin: standard
  (2) fix qeq/reax, perpetual, copy from (1)
      attributes: half, newton off
      pair build: copy
      stencil: none
      bin: none
Setting up Verlet run ...
  Unit style    : real
  Current step  : 0
  Time step     : 0.1
Per MPI rank memory allocation (min/avg/max) = 143.9 | 143.9 | 143.9 Mbytes
   Step          Temp          PotEng         Press          E_vdwl         E_coul         Volume    
         0   300           -113.27833      437.52134     -111.57687     -1.7014647      27418.867    
        10   299.38517     -113.27631      1439.2511     -111.57492     -1.7013814      27418.867    
        20   300.27107     -113.27884      3764.3921     -111.57762     -1.7012246      27418.867    
        30   302.21063     -113.28428      7007.6315     -111.58335     -1.7009364      27418.867    
        40   303.52265     -113.28799      9844.7899     -111.58747     -1.7005187      27418.867    
        50   301.87059     -113.28324      9663.0837     -111.58318     -1.7000523      27418.867    
        60   296.67807     -113.26777      7273.8688     -111.56815     -1.6996136      27418.867    
        70   292.2         -113.25435      5533.5999     -111.55514     -1.6992157      27418.867    
        80   293.58679     -113.25831      5993.3978     -111.55946     -1.6988534      27418.867    
        90   300.62637     -113.27925      7202.8885     -111.58069     -1.6985591      27418.867    
       100   305.38276     -113.29357      10085.741     -111.59518     -1.6983875      27418.867    
Loop time of 9.43821 on 2 procs for 100 steps with 2432 atoms

Performance: 0.092 ns/day, 262.173 hours/ns, 10.595 timesteps/s, 25.768 katom-step/s
99.8% CPU use with 2 MPI tasks x 1 OpenMP threads

MPI task timing breakdown:
Section |  min time  |  avg time  |  max time  |%varavg| %total
---------------------------------------------------------------
Pair    | 6.9119     | 7.0673     | 7.2228     |   5.8 | 74.88
Neigh   | 0.11603    | 0.11763    | 0.11922    |   0.5 |  1.25
Comm    | 0.013927   | 0.16934    | 0.32476    |  37.8 |  1.79
Output  | 0.00029069 | 0.00029232 | 0.00029395 |   0.0 |  0.00
Modify  | 2.0813     | 2.0829     | 2.0845     |   0.1 | 22.07
Other   |            | 0.0006819  |            |       |  0.01

Nlocal:           1216 ave        1216 max        1216 min
Histogram: 2 0 0 0 0 0 0 0 0 0
Nghost:         7591.5 ave        7597 max        7586 min
Histogram: 1 0 0 0 0 0 0 0 0 1
Neighs:         432912 ave      432942 max      432882 min
Histogram: 1 0 0 0 0 0 0 0 0 1

Total # of neighbors = 865824
Ave neighs/atom = 356.01316
Neighbor list builds = 5
Dangerous builds not checked
Total wall time: 0:00:09
```

</details>

To clean up the run, you need to uninstall:

```bash
helm uninstall lammps
```

If you specify more than one iteration (what we often do for running experiments) each will be done.

```bash
helm install \
  --set minicluster.size=1 \
  --set minicluster.image=ghcr.io/converged-computing/metric-lammps-cpu:zen4-reax \
  --set experiment.iterations=2 \
  --set minicluster.addFlux=true \
  lammps ./lammps-reax
```

### 5. Features Supported

#### Flux Metadata

For actual experiments, we usually want to capture the total wrapped duration and other events from the workload manager, and be able to pipe the entire kubectl logs to file that we can parse later. That's easy to add:

```
```bash
helm install \
  --set minicluster.save_logs=true \
  lammps ./lammps-reax
```

Here is how the output file has changed:

<details>

<summary> LAMMPS output with flux events</summary>

```console
Defaulted container "lammps" out of: lammps, flux-view (init)
#!/bin/bash
set -euo pipefail
mkdir -p /tmp/output
flux resource list

for i in {1..1}
do
  echo "FLUX-RUN START lammps-iter-$i"
  flux run --setattr=user.study_id=lammps-iter-$i -N1 -n 2 -o cpu-affinity=per-task -o gpu-affinity=off      /usr/bin/lmp -v x 2 -v y 2 -v z 2 -in in.reaxff.hns -nocite |& tee /tmp/lammps.out
  
   echo "FLUX-RUN END lammps-iter-$i"
done


output=./results/${app}
(apt-get update && apt-get install -y jq) || (yum update -y && yum install -y jq)
mkdir -p $output
for jobid in $(flux jobs -a --json | jq -r .jobs[].id); do
    echo
    study_id=$(flux job info $jobid jobspec | jq -r ".attributes.user.study_id")
    echo "FLUX-JOB START ${jobid} ${study_id}"
    echo "FLUX-JOB-JOBSPEC START"
    flux job info $jobid jobspec
    echo "FLUX-JOB-JOBSPEC END" 
    
    echo "FLUX-JOB-RESOURCES START"
    flux job info ${jobid} R
    echo "FLUX-JOB-RESOURCES END"
    echo "FLUX-JOB-EVENTLOG START" 
    flux job info $jobid guest.exec.eventlog
    echo "FLUX-JOB-EVENTLOG END" 
    echo "FLUX-JOB END ${jobid} ${study_id}"
done
echo "FLUX JOB STATS"
flux job stats         

     STATE NNODES   NCORES    NGPUS NODELIST
      free      1        8        0 lammps-0
 allocated      0        0        0 
      down      0        0        0 
FLUX-RUN START lammps-iter-1
LAMMPS (17 Apr 2024 - Development - a8687b5)
OMP_NUM_THREADS environment is not set. Defaulting to 1 thread. (src/comm.cpp:98)
  using 1 OpenMP thread(s) per MPI task
Reading data file ...
  triclinic box = (0 0 0) to (22.326 11.1412 13.778966) with tilt (0 -5.02603 0)
  2 by 1 by 1 MPI processor grid
  reading atoms ...
  304 atoms
  reading velocities ...
  304 velocities
  read_data CPU = 0.002 seconds
Replication is creating a 2x2x2 = 8 times larger system...
  triclinic box = (0 0 0) to (44.652 22.2824 27.557932) with tilt (0 -10.05206 0)
  2 by 1 by 1 MPI processor grid
  bounding box image = (0 -1 -1) to (0 1 1)
  bounding box extra memory = 0.03 MB
  average # of replicas added to proc = 5.00 out of 8 (62.50%)
  2432 atoms
  replicate CPU = 0.000 seconds
Neighbor list info ...
  update: every = 20 steps, delay = 0 steps, check = no
  max neighbors/atom: 2000, page size: 100000
  master list distance cutoff = 11
  ghost atom cutoff = 11
  binsize = 5.5, bins = 10 5 6
  2 neighbor lists, perpetual/occasional/extra = 2 0 0
  (1) pair reaxff, perpetual
      attributes: half, newton off, ghost
      pair build: half/bin/ghost/newtoff
      stencil: full/ghost/bin/3d
      bin: standard
  (2) fix qeq/reax, perpetual, copy from (1)
      attributes: half, newton off
      pair build: copy
      stencil: none
      bin: none
Setting up Verlet run ...
  Unit style    : real
  Current step  : 0
  Time step     : 0.1
Per MPI rank memory allocation (min/avg/max) = 143.9 | 143.9 | 143.9 Mbytes
   Step          Temp          PotEng         Press          E_vdwl         E_coul         Volume    
         0   300           -113.27833      437.52134     -111.57687     -1.7014647      27418.867    
        10   299.38517     -113.27631      1439.2511     -111.57492     -1.7013814      27418.867    
        20   300.27107     -113.27884      3764.3921     -111.57762     -1.7012246      27418.867    
        30   302.21063     -113.28428      7007.6315     -111.58335     -1.7009364      27418.867    
        40   303.52265     -113.28799      9844.7899     -111.58747     -1.7005187      27418.867    
        50   301.87059     -113.28324      9663.0837     -111.58318     -1.7000523      27418.867    
        60   296.67807     -113.26777      7273.8688     -111.56815     -1.6996136      27418.867    
        70   292.2         -113.25435      5533.5999     -111.55514     -1.6992157      27418.867    
        80   293.58679     -113.25831      5993.3978     -111.55946     -1.6988534      27418.867    
        90   300.62637     -113.27925      7202.8885     -111.58069     -1.6985591      27418.867    
       100   305.38276     -113.29357      10085.741     -111.59518     -1.6983875      27418.867    
Loop time of 9.48714 on 2 procs for 100 steps with 2432 atoms

Performance: 0.091 ns/day, 263.532 hours/ns, 10.541 timesteps/s, 25.635 katom-step/s
99.8% CPU use with 2 MPI tasks x 1 OpenMP threads

MPI task timing breakdown:
Section |  min time  |  avg time  |  max time  |%varavg| %total
---------------------------------------------------------------
Pair    | 6.8829     | 7.0529     | 7.2229     |   6.4 | 74.34
Neigh   | 0.11578    | 0.11587    | 0.11596    |   0.0 |  1.22
Comm    | 0.010545   | 0.18042    | 0.35029    |  40.0 |  1.90
Output  | 0.00031558 | 0.00032584 | 0.0003361  |   0.0 |  0.00
Modify  | 2.1369     | 2.137      | 2.137      |   0.0 | 22.52
Other   |            | 0.0006946  |            |       |  0.01

Nlocal:           1216 ave        1216 max        1216 min
Histogram: 2 0 0 0 0 0 0 0 0 0
Nghost:         7591.5 ave        7597 max        7586 min
Histogram: 1 0 0 0 0 0 0 0 0 1
Neighs:         432912 ave      432942 max      432882 min
Histogram: 1 0 0 0 0 0 0 0 0 1

Total # of neighbors = 865824
Ave neighs/atom = 356.01316
Neighbor list builds = 5
Dangerous builds not checked
Total wall time: 0:00:09
FLUX-RUN END lammps-iter-1
Get:1 http://security.ubuntu.com/ubuntu jammy-security InRelease [129 kB]
Hit:2 http://archive.ubuntu.com/ubuntu jammy InRelease              
Get:3 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages [2901 kB]
Get:4 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [128 kB]
Get:5 http://security.ubuntu.com/ubuntu jammy-security/universe amd64 Packages [1245 kB]
Get:6 http://security.ubuntu.com/ubuntu jammy-security/restricted amd64 Packages [4282 kB]
Get:7 http://archive.ubuntu.com/ubuntu jammy-backports InRelease [127 kB]      
Get:8 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages [3211 kB]
Get:9 http://archive.ubuntu.com/ubuntu jammy-updates/universe amd64 Packages [1546 kB]
Get:10 http://archive.ubuntu.com/ubuntu jammy-updates/restricted amd64 Packages [4436 kB]
Get:11 http://archive.ubuntu.com/ubuntu jammy-backports/main amd64 Packages [83.2 kB]
Fetched 18.1 MB in 2s (8642 kB/s)                            
Reading package lists... Done
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
jq is already the newest version (1.6-2.1ubuntu3).
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.

FLUX-JOB START 6660554752 lammps-iter-1
FLUX-JOB-JOBSPEC START
{"resources": [{"type": "node", "count": 1, "with": [{"type": "slot", "count": 2, "with": [{"type": "core", "count": 1}], "label": "task"}]}], "tasks": [{"command": ["/usr/bin/lmp", "-v", "x", "2", "-v", "y", "2", "-v", "z", "2", "-in", "in.reaxff.hns", "-nocite"], "slot": "task", "count": {"per_slot": 1}}], "attributes": {"system": {"duration": 0, "cwd": "/opt/lammps/examples/reaxff/HNS", "shell": {"options": {"rlimit": {"cpu": -1, "fsize": -1, "data": -1, "stack": 8388608, "core": -1, "nofile": 1048576, "as": -1, "rss": -1, "nproc": -1}, "cpu-affinity": "per-task", "gpu-affinity": "off"}}}, "user": {"study_id": "lammps-iter-1"}}, "version": 1}
FLUX-JOB-JOBSPEC END
FLUX-JOB-RESOURCES START
{"version": 1, "execution": {"R_lite": [{"rank": "0", "children": {"core": "6-7"}}], "nodelist": ["lammps-0"], "starttime": 1746991421, "expiration": 4900591421}}
FLUX-JOB-RESOURCES END
FLUX-JOB-EVENTLOG START
{"timestamp":1746991421.5843747,"name":"init"}
{"timestamp":1746991421.5915587,"name":"shell.init","context":{"service":"0-shell-fB9a5su","leader-rank":0,"size":1}}
{"timestamp":1746991421.5945508,"name":"shell.start","context":{"taskmap":{"version":1,"map":[[0,1,2,1]]}}}
{"timestamp":1746991421.5846651,"name":"starting"}
{"timestamp":1746991432.7146101,"name":"shell.task-exit","context":{"localid":1,"rank":1,"state":"Exited","pid":107,"wait_status":0,"signaled":0,"exitcode":0}}
{"timestamp":1746991432.7171538,"name":"complete","context":{"status":0}}
{"timestamp":1746991432.7171805,"name":"done"}

FLUX-JOB-EVENTLOG END
FLUX-JOB END 6660554752 lammps-iter-1
FLUX JOB STATS
{"job_states":{"depend":0,"priority":0,"sched":0,"run":0,"cleanup":0,"inactive":1,"total":1},"successful":1,"failed":0,"canceled":0,"timeout":0,"inactive_purged":0,"queues":[]}
```

</details>

We have functions that are useful to parse the log from metadata that we will provide in an associated library.

#### Running Modes

The normal running mode assumes a distributed application (across node) and simply runs iterations and prints application output from the lead broker. However, we have a few custom modes for different cases.

##### 1. Select combinations of pairs

For paired runs (between pairs of nodes) you might want to run something that selects samples from pairs. We support that with `experiment.pairs`. Here is how to select 28 combinations, 8 nodes (the pairs parameter), 2 at a time, for a loop over three OSU benchmarks. This is intended to run in kind on a local machine, but you'd want to adjust the sizes for your cluster.

```bash
helm dependency update osu-benchmarks
for app in osu_latency osu_bw
  do
  helm install \
  --set experiment.nodes=8 \
  --set minicluster.size=8 \
  --set minicluster.tasks=12 \
  --set minicluster.save_logs=true \
  --set experiment.pairs=8 \
  --set osu.binary=/opt/osu-benchmark/build.openmpi/mpi/pt2pt/$app \
  --set experiment.tasks=2 \
  osu osu-benchmarks/
  sleep 5
  time kubectl wait --for=condition=ready pod -l job-name=osu --timeout=600s
  pod=$(kubectl get pods -o json | jq  -r .items[0].metadata.name)
  kubectl logs ${pod} -f
  helm uninstall osu
done
```

The `sleep` isn't explicitly necessary, but rarely the deployment is slow enough that it will skip and cause an error in the next line. To save to an output file, you would change the second to the last line in the loop:

```bash
  kubectl logs ${pod} -f |& tee ./logs/$app.out
```

##### 2. Single Node Execution

If you have a single node benchmark, you might want to run one instance on each node in the cluster.  Here is an example of doing that with our single node benchmark.

```bash
helm dependency update ./single-node
helm install \
  --set experiment.nodes=2 \
  --set minicluster.size=2 \
  --set minicluster.tasks=8 \
  --set experiment.tasks=1 \
  --set minicluster.save_logs=true \
  --set minicluster.show_logs=true \
  --set experiment.foreach=true \
  --set experiment.iterations=1 \
  single-node ./single-node

time kubectl wait --for=condition=ready pod -l job-name=single-node --timeout=600s
pod=$(kubectl get pods -o json | jq  -r .items[0].metadata.name)
kubectl logs ${pod} -f
helm uninstall single-node
```

For this setup, you'll see `flux submit` so the jobs will run at the same time on single nodes. Then output is presented later, with the flux events. This is why you want to set `minicluster.show_logs=true` to see that output.

##### 3. Monitor with BCC

This setup will deploy a sidecar and monitor different interacts with bcc. We have several programs that help to understand tcp, file open/closes, cpu, shared memory, or futex wait times. There are two approaches:

- Multiple sidecars per pod (adds overhead, but is acceptable given what the HPC community already does) and the benefit is measuring the same thing between applications.
- Single sidecar per pod (and metrics distributed across cluster) low to zero overhead, and better for summary metrics or models. We an algorithm to select from the set of programs you requested. 

Although for both approaches you can filter to a cgroup or command, for the default we allow all containers in the pod to be seen. It generates a lot more data, but is interesting. Here is how to select a metric for a single sidecar per pod method:

```bash
helm install \
  --set monitor.programs=open_close \
  --set minicluster.save_logs=true \
  --dry-run lammps ./lammps-reax
```

<details>

```console
Looking for /opt/programs/open-close/ebpf-collect.c
Starting eBPF (Tracepoint for open entry).

Start Indicator file defined '/mnt/flux/start_ebpf_collection'. Waiting.
{"event": "OPEN", "command": "python3", "retval": 12, "ts_sec": 779.540036095, "tgid": 0, "tid": 14554, "ppid": 14554, "cgroup_id": 0, "filename": "/sys/bus/event_source/devices/kprobe/type"}
{"event": "OPEN", "command": "python3", "retval": 12, "ts_sec": 779.540051234, "tgid": 0, "tid": 14554, "ppid": 14554, "cgroup_id": 0, "filename": "/sys/bus/event_source/devices/kprobe/format/retprobe"}
{"event": "OPEN", "command": "containerd", "retval": 193, "ts_sec": 779.629315113, "tgid": 0, "tid": 3600, "ppid": 3618, "cgroup_id": 0, "filename": "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/204/fs"}
{"event": "CLOSE", "command": "containerd", "retval": 0, "ts_sec": 779.629342785, "tgid": 1, "tid": 3600, "ppid": 3618, "cgroup_id": 6520}
...
{"event": "OPEN", "command": "touch", "retval": 3, "ts_sec": 803.043308743, "tgid": 0, "tid": 14883, "ppid": 14883, "cgroup_id": 3257288213055174703, "filename": "/usr/lib/locale/C.utf8/LC_NUMERIC"}
{"event": "CLOSE", "command": "touch", "retval": 0, "ts_sec": 803.043310733, "tgid": 14414, "tid": 14883, "ppid": 14883, "cgroup_id": 13176}
{"event": "OPEN", "command": "touch", "retval": 3, "ts_sec": 803.043316595, "tgid": 0, "tid": 14883, "ppid": 14883, "cgroup_id": 3257288213055174703, "filename": "/usr/lib/locale/C.utf8/LC_CTYPE"}
{"event": "CLOSE", "command": "touch", "retval": 0, "ts_sec": 803.043318514, "tgid": 14414, "tid": 14883, "ppid": 14883, "cgroup_id": 13176}
{"event": "OPEN", "command": "touch", "retval": 3, "ts_sec": 803.043359627, "tgid": 0, "tid": 14883, "ppid": 14883, "cgroup_id": 3257288213055174703, "filename": "/mnt/flux/stop_ebpf_collection"}
{"event": "CLOSE", "command": "touch", "retval": 0, "ts_sec": 803.043360931, "tgid": 14414, "tid": 14883, "ppid": 14883, "cgroup_id": 13176}

Indicator file '/mnt/flux/stop_ebpf_collection' found. Stopping.
Cleaning up BPF resources...
```

</details>

Here is how to do multiple at once (each still a single sidecar)

```bash
helm install \
  --set monitor.programs="cpu|shmem|tcp|futex|open_close" \
  --set minicluster.save_logs=true \
  lammps ./lammps-reax
```

Here is how to deploy multiple sidecars:

```bash
helm install \
  --set monitor.multiple=flamegraph|open_close \
  --set monitor.sleep=true \
  --set minicluster.save_logs=true \
  --dry-run lammps ./lammps-reax
```

For the flamegraph, you'll want to enable the monitor container to sleep so you can copy svg and folded files out after.

### 5. Delete

To clean up:

```bash
helm uninstall lammps
```

## Examples

Here are all the examples.  For any example, you need to update dependencies before you run:

```bash
helm dependency update ./<app>
```
```bash
helm install amg ./amg2023
helm install kripke ./kripke
helm install lammps ./lammps-reax
helm install laghos ./laghos
helm install minife ./minife
helm install mtgemm ./mixbench
helm install mtgemm ./mt-gemm
helm install stream ./osu-benchmarks
helm install stream ./quicksilver
helm install stream ./single-node
helm install stream ./stream
```

And an example to use a custom yaml file (more ideal for reproducible experiments):

```bash
helm install amg -f ./examples/amg2023/flux-minicluster.yaml ./amg2023
```

## License

HPCIC DevTools is distributed under the terms of the MIT license.
All new contributions must be made under this license.

See [LICENSE](https://github.com/converged-computing/cloud-select/blob/main/LICENSE),
[COPYRIGHT](https://github.com/converged-computing/cloud-select/blob/main/COPYRIGHT), and
[NOTICE](https://github.com/converged-computing/cloud-select/blob/main/NOTICE) for details.

SPDX-License-Identifier: (MIT)

LLNL-CODE- 842614


