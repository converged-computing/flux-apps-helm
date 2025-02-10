# Flux Operator Apps

These are simple helm charts to run HPC applications in Kubernetes using the Flux Operator. You can customize each different application to your needs, from the container, to size, to iterations, etc. We have a simple strategy that uses:

 - [base-template](base-template): A base template MiniCluster that is used acrossed apps.
 - Applications:
   - [lammps-reax](lammps-reax): for running the hns-reaxff app.

## Overview

For the applications above (more to come) they can be customized for anything related to the MiniCluster (e.g., size, flux view, logging, TBA resources), and anything related to the application itself (parameters, containers, etc). Given the use of a common template, the actual definition of the application is fairly small (and thus they are easy to write). This is a nice approach because:

- We don't require extra software installed into the MiniCluster
- An application definition is simple (and can be written easily / quickly)
- Changing logic for the MiniCluster only needs to be done in one place!
- Applications can be proggramatically built and tested (TBA)
- Experiments can be orchestrated via using these helm charts with a custom values.yaml for each application (example will likely be provided in the future).

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

```bash
# Create the cluster
kind create cluster --config ./kind-config.yaml

# Install the Flux Operator
kubectl apply -f https://raw.githubusercontent.com/flux-framework/flux-operator/refs/heads/main/examples/dist/flux-operator.yaml
```

### 2. View Values

Here are the values we can customize (any can be exposed really, it's very simple).

```bash
$ helm show values ./lammps-reax
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
  tasks: 4
  
lammps:
  binary: /usr/bin/lmp
  input: in.reaxff.hns
  x: 2
  y: 2
  z: 2
  
minicluster:
  # Container image
  image: "ghcr.io/converged-computing/metric-lammps-cpu:zen4-reax"

  # Interactive MiniCluster?
  interactive: false
  
  # MiniCluster size
  size: 1
  
  # Minicluster tasks
  tasks: 4

  # Add flux on the fly (set to false if Flux is already in the container)
  addFlux: true
```

If there are changes to the base template:

```bash
helm dependency update lammps-reax/
helm install lammps lammps-reax/ --debug --dry-run
```

### 3. Install LAMMPS Chart

Then install the chart. This will deploy the Flux MiniCluster and run lammps for some number of iterations. All variables are technically defined so you don't need any `--set`.

```bash
helm install \
  --set minicluster.size=1 \
  --set minicluster.image=ghcr.io/converged-computing/metric-lammps-cpu:zen4-reax \
  lammps ./lammps-reax
```
```console
NAME: lammps
LAST DEPLOYED: Sat Feb  8 18:28:52 2025
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
```console
#!/bin/bash
mkdir -p /tmp/output
for i in 1
do
  echo "Running iteration ${i}"
  cmd='flux run -N1 -n 4 -o cpu-affinity=per-task /usr/bin/lmp -v x 2 -v y 2 -v z 2 -in in.reaxff.hns -nocite'
  $cmd >> /tmp/lammps.out
done
Running iteration 1
LAMMPS (17 Apr 2024 - Development - a8687b5)
OMP_NUM_THREADS environment is not set. Defaulting to 1 thread. (src/comm.cpp:98)
  using 1 OpenMP thread(s) per MPI task
Reading data file ...
  triclinic box = (0 0 0) to (22.326 11.1412 13.778966) with tilt (0 -5.02603 0)
  2 by 1 by 2 MPI processor grid
  reading atoms ...
  304 atoms
  reading velocities ...
  304 velocities
  read_data CPU = 0.003 seconds
Replication is creating a 2x2x2 = 8 times larger system...
  triclinic box = (0 0 0) to (44.652 22.2824 27.557932) with tilt (0 -10.05206 0)
  2 by 1 by 2 MPI processor grid
  bounding box image = (0 -1 -1) to (0 1 1)
  bounding box extra memory = 0.03 MB
  average # of replicas added to proc = 5.00 out of 8 (62.50%)
  2432 atoms
  replicate CPU = 0.001 seconds
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
Per MPI rank memory allocation (min/avg/max) = 103.8 | 103.8 | 103.8 Mbytes
   Step          Temp          PotEng         Press          E_vdwl         E_coul         Volume    
         0   300           -113.27833      437.52125     -111.57687     -1.7014647      27418.867    
        10   299.38517     -113.27631      1439.2564     -111.57492     -1.7013814      27418.867    
        20   300.27106     -113.27884      3764.3691     -111.57762     -1.7012246      27418.867    
        30   302.21062     -113.28428      7007.6981     -111.58335     -1.7009363      27418.867    
        40   303.52264     -113.28799      9844.8446     -111.58747     -1.7005186      27418.867    
        50   301.87059     -113.28324      9663.0539     -111.58318     -1.7000523      27418.867    
        60   296.67807     -113.26777      7273.8217     -111.56815     -1.6996137      27418.867    
        70   292.19997     -113.25435      5533.6159     -111.55514     -1.6992157      27418.867    
        80   293.58676     -113.25831      5993.3876     -111.55946     -1.6988534      27418.867    
        90   300.62635     -113.27925      7202.8554     -111.58069     -1.6985591      27418.867    
       100   305.38277     -113.29357      10085.756     -111.59518     -1.6983875      27418.867    
Loop time of 6.94078 on 4 procs for 100 steps with 2432 atoms

Performance: 0.124 ns/day, 192.799 hours/ns, 14.408 timesteps/s, 35.039 katom-step/s
99.3% CPU use with 4 MPI tasks x 1 OpenMP threads

MPI task timing breakdown:
Section |  min time  |  avg time  |  max time  |%varavg| %total
---------------------------------------------------------------
Pair    | 4.6564     | 5.0021     | 5.3776     |  12.4 | 72.07
Neigh   | 0.08552    | 0.088538   | 0.094817   |   1.2 |  1.28
Comm    | 0.024183   | 0.39984    | 0.74567    |  43.7 |  5.76
Output  | 0.00027993 | 0.00029865 | 0.0003209  |   0.0 |  0.00
Modify  | 1.4428     | 1.449      | 1.4519     |   0.3 | 20.88
Other   |            | 0.001043   |            |       |  0.02

Nlocal:            608 ave         612 max         604 min
Histogram: 1 0 0 0 0 2 0 0 0 1
Nghost:        5737.25 ave        5744 max        5732 min
Histogram: 1 0 1 0 0 1 0 0 0 1
Neighs:         231539 ave      233090 max      229970 min
Histogram: 1 0 0 0 1 1 0 0 0 1

Total # of neighbors = 926155
Ave neighs/atom = 380.82031
Neighbor list builds = 5
Dangerous builds not checked
Total wall time: 0:00:07
```

If you specify more than one iteration, it will be there too.


At this point we might upload them somewhere, and arguably this could be done in the template.

### 4. Delete

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

## License

HPCIC DevTools is distributed under the terms of the MIT license.
All new contributions must be made under this license.

See [LICENSE](https://github.com/converged-computing/cloud-select/blob/main/LICENSE),
[COPYRIGHT](https://github.com/converged-computing/cloud-select/blob/main/COPYRIGHT), and
[NOTICE](https://github.com/converged-computing/cloud-select/blob/main/NOTICE) for details.

SPDX-License-Identifier: (MIT)

LLNL-CODE- 842614


