# Flux Operator Apps

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
NODES=2
GOOGLE_PROJECT=myproject
INSTANCE=h3-standard-88

time gcloud container clusters create test-cluster  \
   --threads-per-core=1  \   
   --num-nodes=$NODES  \   
   --machine-type=$INSTANCE  \
   --placement-type=COMPACT  \   
   --image-type=UBUNTU_CONTAINERD \
   --region=us-central1-a     --project=${GOOGLE_PROJECT}
```

Finally, install the Flux Operator

```bash
# Install the Flux Operator
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

This setup will deploy a sidecar and monitor different interacts with bcc.

```bash
helm install \
  --set experiment.monitor=true \
  --set minicluster.save_logs=true \
  lammps ./lammps-reax
```

You'll need to look at the logs to see the sidecar vs. lammps.

```bash
kubeclt lo
```

Try changing the command:

```bash
helm install \
  --set experiment.monitor=true \
  --set minicluster.save_logs=true \
  --set minicluster.monitor_command="tcplife-bpfcc -stT" \
  lammps ./lammps-reax
```

##### 4. Recording

**WARNING EXPERIMENTAL**

We use [fs-record from the compat-lib](https://github.com/compspec/compat-lib/) library, a tool written by the same authors here that can deploy a fuse fs in the context of the container to easily record (path and time) for all filesystem requests. You can run that with your application and add the recording to your output. Here is an example with lammps:

```bash
helm install \
  --set experiment.record=true \
  --set minicluster.save_logs=true \
  lammps ./lammps-reax
```

This will give you the libraries and data loaded with timestamps. Note that this will install libfuse and proot in your container, and is run with admin privileges.

<details>

<summary>LAMMPS Run with recording output</summary>

```console
#!/bin/bash
set -euo pipefail
mkdir -p /tmp/output
flux resource list
for i in {1..1}
do
  echo "FLUX-RUN START lammps-iter-$i"
  flux run --setattr=user.study_id=lammps-iter-$i -N2 -n 2 -o cpu-affinity=per-task -o gpu-affinity=off     fs-record --out /tmp/recording.out --mpi /usr/bin/lmp -v x 2 -v y 2 -v z 2 -in in.reaxff.hns -nocite
  
   echo "FLUX-RUN END lammps-iter-$i"
done


output=./results/${app}
(apt-get update > /dev/null 2>&1 && apt-get install -y jq > /dev/null 2>&1) || (yum update -y > /dev/null 2>&1 && yum install -y jq > /dev/null 2>&1)
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
      free      2       16        0 lammps-[0-1]
 allocated      0        0        0 
      down      0        0        0 
FLUX-RUN START lammps-iter-1
⭐️ Filesystem Recorder (fs-record)
MPI Rank 1 preparing to just PRoot.
Found rank 1
Mount directory /tmp/recordfs3577121016
⭐️ Filesystem Recorder (fs-record)
MPI Rank 0 (or master) preparing to create fuseFS and launch LAMMPS via PRoot.
Found rank 0
Mount directory /tmp/recordfs1944570715
proot -S /tmp/recordfs3577121016 -0 /usr/bin/lmp -v x 2 -v y 2 -v z 2 -in in.reaxff.hns -nocite
proot -S /tmp/recordfs1944570715 -0 /usr/bin/lmp -v x 2 -v y 2 -v z 2 -in in.reaxff.hns -nocite
WARNING on proc 0: Cannot open log.lammps for writing: Read-only file system (src/lammps.cpp:511)
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
  read_data CPU = 0.008 seconds
Replication is creating a 2x2x2 = 8 times larger system...
  triclinic box = (0 0 0) to (44.652 22.2824 27.557932) with tilt (0 -10.05206 0)
  2 by 1 by 1 MPI processor grid
  bounding box image = (0 -1 -1) to (0 1 1)
  bounding box extra memory = 0.03 MB
  average # of replicas added to proc = 5.00 out of 8 (62.50%)
  2432 atoms
  replicate CPU = 0.003 seconds
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
Loop time of 13.5318 on 2 procs for 100 steps with 2432 atoms

Performance: 0.064 ns/day, 375.882 hours/ns, 7.390 timesteps/s, 17.973 katom-step/s
84.8% CPU use with 2 MPI tasks x 1 OpenMP threads

MPI task timing breakdown:
Section |  min time  |  avg time  |  max time  |%varavg| %total
---------------------------------------------------------------
Pair    | 8.7732     | 9.097      | 9.4209     |  10.7 | 67.23
Neigh   | 0.16177    | 0.16214    | 0.16251    |   0.1 |  1.20
Comm    | 0.057228   | 0.3815     | 0.70578    |  52.5 |  2.82
Output  | 0.0056962  | 0.0057224  | 0.0057486  |   0.0 |  0.04
Modify  | 3.8836     | 3.8844     | 3.8853     |   0.0 | 28.71
Other   |            | 0.0008951  |            |       |  0.01

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
Total wall time: 0:00:13
Command is done running
Command is done running
Cleaning up /tmp/recordfs3577121016...
Output file written to /tmp/recording.out
Cleaning up /tmp/recordfs1944570715...
Output file written to /tmp/recording.out
FLUX-RUN END lammps-iter-1

FLUX-JOB START 32396804096 lammps-iter-1
FLUX-JOB-JOBSPEC START
{"resources": [{"type": "node", "count": 2, "with": [{"type": "slot", "count": 1, "with": [{"type": "core", "count": 1}], "label": "task"}]}], "tasks": [{"command": ["fs-record", "--out", "/tmp/recording.out", "--mpi", "/usr/bin/lmp", "-v", "x", "2", "-v", "y", "2", "-v", "z", "2", "-in", "in.reaxff.hns", "-nocite"], "slot": "task", "count": {"per_slot": 1}}], "attributes": {"system": {"duration": 0, "cwd": "/opt/lammps/examples/reaxff/HNS", "shell": {"options": {"rlimit": {"cpu": -1, "fsize": -1, "data": -1, "stack": 8388608, "core": -1, "nofile": 1048576, "as": -1, "rss": -1, "nproc": -1}, "cpu-affinity": "per-task", "gpu-affinity": "off"}}}, "user": {"study_id": "lammps-iter-1"}}, "version": 1}
FLUX-JOB-JOBSPEC END
FLUX-JOB-RESOURCES START
{"version": 1, "execution": {"R_lite": [{"rank": "0-1", "children": {"core": "7"}}], "nodelist": ["lammps-[0-1]"], "starttime": 1747009489, "expiration": 4900609487}}
FLUX-JOB-RESOURCES END
FLUX-JOB-EVENTLOG START
{"timestamp":1747009489.0643024,"name":"init"}
{"timestamp":1747009489.0732028,"name":"shell.init","context":{"service":"0-shell-frMo6As","leader-rank":0,"size":2}}
{"timestamp":1747009489.0646524,"name":"starting"}
{"timestamp":1747009489.0766976,"name":"shell.start","context":{"taskmap":{"version":1,"map":[[0,2,1,1]]}}}
{"timestamp":1747009504.721137,"name":"shell.task-exit","context":{"localid":0,"rank":1,"state":"Exited","pid":338,"wait_status":0,"signaled":0,"exitcode":0}}
{"timestamp":1747009504.7251501,"name":"complete","context":{"status":0}}
{"timestamp":1747009504.7251644,"name":"done"}

FLUX-JOB-EVENTLOG END
FLUX-JOB END 32396804096 lammps-iter-1
FLUX JOB STATS
{"job_states":{"depend":0,"priority":0,"sched":0,"run":0,"cleanup":0,"inactive":1,"total":1},"successful":1,"failed":0,"canceled":0,"timeout":0,"inactive_purged":0,"queues":[]}
RECORD-START
2025/05/12 00:24:49 logger.go:63: 1747009489082404479 Lookup    /etc      
2025/05/12 00:24:49 logger.go:63: 1747009489082575601 Lookup    /etc/host.conf
2025/05/12 00:24:49 logger.go:63: 1747009489082633060 Lookup    /etc/hosts
2025/05/12 00:24:49 logger.go:63: 1747009489082684998 Lookup    /etc/nsswitch.conf
2025/05/12 00:24:49 logger.go:63: 1747009489082723440 Lookup    /etc/resolv.conf
2025/05/12 00:24:49 logger.go:63: 1747009489082766231 Lookup    /dev      
2025/05/12 00:24:49 logger.go:63: 1747009489082794304 Lookup    /sys      
2025/05/12 00:24:49 logger.go:63: 1747009489082818740 Lookup    /proc     
2025/05/12 00:24:49 logger.go:63: 1747009489082864196 Lookup    /tmp      
2025/05/12 00:24:49 logger.go:63: 1747009489082890696 Lookup    /root     
2025/05/12 00:24:49 logger.go:63: 1747009489083012726 Lookup    /opt      
2025/05/12 00:24:49 logger.go:63: 1747009489083070094 Lookup    /opt/lammps
2025/05/12 00:24:49 logger.go:63: 1747009489083112945 Lookup    /opt/lammps/examples
2025/05/12 00:24:49 logger.go:63: 1747009489083159263 Lookup    /opt/lammps/examples/reaxff
2025/05/12 00:24:49 logger.go:63: 1747009489083195571 Lookup    /opt/lammps/examples/reaxff/HNS
2025/05/12 00:24:49 logger.go:63: 1747009489083253841 Lookup    /usr      
2025/05/12 00:24:49 logger.go:63: 1747009489083285922 Lookup    /usr/bin  
2025/05/12 00:24:49 logger.go:63: 1747009489083328812 Lookup    /usr/bin/lmp
2025/05/12 00:24:49 logger.go:63: 1747009489083732785 Open      /usr/bin/lmp	7
2025/05/12 00:24:49 logger.go:63: 1747009489083846930 Close     /usr/bin/lmp	7
2025/05/12 00:24:49 logger.go:63: 1747009489083930939 Open      /usr/bin/lmp	18
2025/05/12 00:24:49 logger.go:63: 1747009489084009457 Lookup    /lib64    
2025/05/12 00:24:49 logger.go:63: 1747009489084048691 Lookup    /usr/lib64
2025/05/12 00:24:49 logger.go:63: 1747009489084163738 Lookup    /usr/lib64/ld-linux-x86-64.so.2
2025/05/12 00:24:49 logger.go:63: 1747009489084256102 Lookup    /lib      
2025/05/12 00:24:49 logger.go:63: 1747009489084307239 Lookup    /usr/lib  
2025/05/12 00:24:49 logger.go:63: 1747009489084395515 Lookup    /usr/lib/x86_64-linux-gnu
2025/05/12 00:24:49 logger.go:63: 1747009489084432034 Lookup    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
2025/05/12 00:24:49 logger.go:63: 1747009489084527154 Close     /usr/bin/lmp	18
2025/05/12 00:24:49 logger.go:63: 1747009489084576737 Open      /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	20
2025/05/12 00:24:49 logger.go:63: 1747009489084685532 Close     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	20
2025/05/12 00:24:49 logger.go:63: 1747009489085520929 Open      /usr/bin/lmp	21
2025/05/12 00:24:49 logger.go:63: 1747009489085806397 Close     /usr/bin/lmp	21
2025/05/12 00:24:49 logger.go:63: 1747009489086149986 Open      /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	22
2025/05/12 00:24:49 logger.go:63: 1747009489086407371 Close     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	22
2025/05/12 00:24:49 logger.go:63: 1747009489087117601 Lookup    /usr/lib/flux
2025/05/12 00:24:49 logger.go:63: 1747009489091722470 Lookup    /usr/local
2025/05/12 00:24:49 logger.go:63: 1747009489091771662 Lookup    /usr/local/lib
2025/05/12 00:24:49 logger.go:63: 1747009489094457640 Lookup    /etc/ld.so.cache
2025/05/12 00:24:49 logger.go:63: 1747009489094521852 Open      /etc/ld.so.cache	23
2025/05/12 00:24:49 logger.go:63: 1747009489094643251 Close     /etc/ld.so.cache	23
2025/05/12 00:24:49 logger.go:63: 1747009489094895777 Lookup    /usr/lib/x86_64-linux-gnu/libgomp.so.1
2025/05/12 00:24:49 logger.go:63: 1747009489094963064 Lookup    /usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0
2025/05/12 00:24:49 logger.go:63: 1747009489095056971 Open      /usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0	24
2025/05/12 00:24:49 logger.go:63: 1747009489095411841 Close     /usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0	24
2025/05/12 00:24:49 logger.go:63: 1747009489095796246 Lookup    /usr/local/lib/libmpi.so.40
2025/05/12 00:24:49 logger.go:63: 1747009489095850889 Lookup    /usr/local/lib/libmpi.so.40.30.2
2025/05/12 00:24:49 logger.go:63: 1747009489095976356 Open      /usr/local/lib/libmpi.so.40.30.2	25
2025/05/12 00:24:49 logger.go:63: 1747009489096451913 Close     /usr/local/lib/libmpi.so.40.30.2	25
2025/05/12 00:24:49 logger.go:63: 1747009489097040714 Lookup    /usr/lib/x86_64-linux-gnu/libjpeg.so.8
2025/05/12 00:24:49 logger.go:63: 1747009489097104995 Lookup    /usr/lib/x86_64-linux-gnu/libjpeg.so.8.2.2
2025/05/12 00:24:49 logger.go:63: 1747009489097225272 Open      /usr/lib/x86_64-linux-gnu/libjpeg.so.8.2.2	26
2025/05/12 00:24:49 logger.go:63: 1747009489097561988 Close     /usr/lib/x86_64-linux-gnu/libjpeg.so.8.2.2	26
2025/05/12 00:24:49 logger.go:63: 1747009489098108369 Lookup    /usr/lib/x86_64-linux-gnu/libstdc++.so.6
2025/05/12 00:24:49 logger.go:63: 1747009489098164114 Lookup    /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30
2025/05/12 00:24:49 logger.go:63: 1747009489098294690 Open      /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30	27
2025/05/12 00:24:49 logger.go:63: 1747009489098742305 Close     /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30	27
2025/05/12 00:24:49 logger.go:63: 1747009489099317740 Lookup    /usr/lib/x86_64-linux-gnu/libm.so.6
...
2025/05/12 00:24:49 logger.go:63: 1747009489778578102 Close     /usr/local/lib/openmpi/mca_osc_rdma.so	163
2025/05/12 00:24:49 logger.go:63: 1747009489778908545 Open      /usr/local/lib/openmpi/mca_osc_pt2pt.so	164
2025/05/12 00:24:49 logger.go:63: 1747009489779238077 Close     /usr/local/lib/openmpi/mca_osc_pt2pt.so	164
2025/05/12 00:24:49 logger.go:63: 1747009489779536951 Open      /usr/local/lib/openmpi/mca_osc_monitoring.so	165
2025/05/12 00:24:49 logger.go:63: 1747009489779887783 Close     /usr/local/lib/openmpi/mca_osc_monitoring.so	165
2025/05/12 00:24:49 logger.go:63: 1747009489780111896 Open      /usr/local/lib/openmpi/mca_osc_sm.so	166
2025/05/12 00:24:49 logger.go:63: 1747009489780409027 Close     /usr/local/lib/openmpi/mca_osc_sm.so	166
2025/05/12 00:24:49 logger.go:63: 1747009489805809993 Lookup    /opt/lammps/examples/reaxff/HNS/in.reaxff.hns
2025/05/12 00:24:49 logger.go:63: 1747009489805891667 Open      /opt/lammps/examples/reaxff/HNS/in.reaxff.hns	167
2025/05/12 00:24:49 logger.go:63: 1747009489818555912 Lookup    /opt/lammps/examples/reaxff/HNS/data.hns-equil
2025/05/12 00:24:49 logger.go:63: 1747009489818641955 Open      /opt/lammps/examples/reaxff/HNS/data.hns-equil	168
2025/05/12 00:24:49 logger.go:63: 1747009489818700285 Close     /opt/lammps/examples/reaxff/HNS/data.hns-equil	168
2025/05/12 00:24:49 logger.go:63: 1747009489818799522 Open      /opt/lammps/examples/reaxff/HNS/data.hns-equil	169
2025/05/12 00:24:49 logger.go:63: 1747009489820397096 Open      /usr/local/lib/openmpi/mca_topo_basic.so	170
2025/05/12 00:24:49 logger.go:63: 1747009489820706680 Close     /usr/local/lib/openmpi/mca_topo_basic.so	170
2025/05/12 00:24:49 logger.go:63: 1747009489820986478 Open      /usr/local/lib/openmpi/mca_topo_treematch.so	171
2025/05/12 00:24:49 logger.go:63: 1747009489821434424 Close     /usr/local/lib/openmpi/mca_topo_treematch.so	171
2025/05/12 00:24:49 logger.go:63: 1747009489825978107 Close     /opt/lammps/examples/reaxff/HNS/data.hns-equil	169
2025/05/12 00:24:49 logger.go:63: 1747009489829500813 Lookup    /opt/lammps/examples/reaxff/HNS/ffield.reax.hns
2025/05/12 00:24:49 logger.go:63: 1747009489829579943 Open      /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	172
2025/05/12 00:24:49 logger.go:63: 1747009489829657218 Close     /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	172
2025/05/12 00:24:49 logger.go:63: 1747009489829763890 Open      /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	173
2025/05/12 00:24:49 logger.go:63: 1747009489829899976 Close     /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	173
2025/05/12 00:24:49 logger.go:63: 1747009489830011246 Open      /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	174
2025/05/12 00:24:49 logger.go:63: 1747009489830152483 Close     /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	174
2025/05/12 00:24:49 logger.go:63: 1747009489830253934 Open      /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	175
2025/05/12 00:24:49 logger.go:63: 1747009489830796448 Close     /opt/lammps/examples/reaxff/HNS/ffield.reax.hns	175
2025/05/12 00:25:03 logger.go:63: 1747009503699984196 Close     /opt/lammps/examples/reaxff/HNS/in.reaxff.hns	167
2025/05/12 00:25:04 logger.go:63: 1747009504714801719 Complete  /tmp/recording.out
RECORD-FINISH
```

</details>

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


