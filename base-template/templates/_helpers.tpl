{{/* Expand the name of the chart. */}}
{{- define "chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "chart.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "chart.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels */}}
{{- define "chart.labels" -}}
helm.sh/chart: {{ include "chart.chart" . }}
{{ include "chart.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Flux Run Serial */}}
{{- define "chart.fluxrun" -}}
         for i in {1..{{ default 1 .Values.experiment.iterations}}}
         do
           echo "FLUX-RUN START $app-iter-\$i"
           flux run --setattr=user.study_id=$app-iter-\$i -N{{ if .Values.experiment.nodes }}{{ .Values.experiment.nodes }}{{ else }}1{{ end }} {{ if .Values.experiment.tasks }}-n {{ .Values.experiment.tasks }}{{ end }} {{ include "chart.fluxopts" . }} ${apprun}
           {{ if .Values.minicluster.commands_post_iteration }}{{ .Values.minicluster.commands_post_iteration }};{{ end }}
            echo "FLUX-RUN END $app-iter-\$i"
         done
{{- end }}


{{/* Flux Run For Each (node) */}}
{{- define "chart.foreach" -}}
         {{- $node_max :=  sub .Values.experiment.nodes 1 -}}
         for i in {1..{{ default 1 .Values.experiment.iterations}}}
         do
           echo "FLUX-RUN START $app-iter-\$i"
           for node in \$(seq 0 {{ default 1 $node_max }}); do
               flux submit --flags waitable --requires="hosts:$app-\$node" -N 1 --setattr=user.study_id=$app-iter-\$i-node-\$node {{ if .Values.experiment.tasks }}-n {{ .Values.experiment.tasks }}{{ end }} {{ include "chart.fluxopts" . }}  ${apprun}               
           done 
           echo "FLUX-RUN END $app-iter-\$i"
         done
         flux job wait --all
{{- end }}

{{/* Flux Shared Options */}}
{{- define "chart.fluxopts" -}}-o cpu-affinity={{ default "per-task" .Values.experiment.cpu_affinity }} -o gpu-affinity={{ default "off" .Values.experiment.gpu_affinity }} {{ if .Values.experiment.run_threads }}--env OMP_NUM_THREADS={{ .Values.experiment.run_threads }}{{ end }} {{ if .Values.experiment.cores_per_task }}--cores-per-task {{ .Values.experiment.cores_per_task }}{{ end }} {{ if .Values.minicluster.gpus }} -g {{ .Values.minicluster.gpus }}{{ end }} {{ if .Values.experiment.exclusive }}--exclusive{{ end }}{{- end }}

{{/* Flux Run with Pairs 
Iterations is not relevant for this one
*/}}
{{- define "chart.fluxpairs" -}}
         # At most 28 combinations, 8 nodes 2 at a time
         hosts=\$(flux run -N{{ default "2" .Values.experiment.nodes }} hostname | shuf -n {{ default "8" .Values.experiment.pairs }} | tr '\n' ' ')
         list=\${hosts}
         dequeue_from_list() {
           shift;
           list=\$@
         }
         iter=0
         for i in \$hosts; do
           dequeue_from_list \$list
           for j in \$list; do
             echo "FLUX-RUN START $app-iter-\${i}-\${j}"
              flux run -N 2 {{ if .Values.experiment.tasks }}-n {{ .Values.experiment.tasks }}{{ end }}  \
               --setattr=user.study_id=$app-iter-\$i-\${j} \
               --requires="hosts:\${i},\${j}" \
               {{ include "chart.fluxopts" . }} \
                ${apprun}
             iter=\$((iter+1))
             echo "FLUX-RUN END $app-iter-\${i}-\${j}"
         done
         done                  
{{- end }}

{{ define "chart.monitor" }}
  {{ if .Values.experiment.monitor }}{{- $progs := .Values.experiment.monitor | splitList "|" }}
  - image: "ghcr.io/converged-computing/bcc-sidecar:ubuntu2204"
    name: bcc-monitor
    runFlux: false
    pullAlways: true 
    securityContext:
      addCapabilities: [SYS_ADMIN, BPF, PERFMON]
      privileged: true
    volumes:
      modules:
        hostPath: /lib/modules
        path: /lib/modules
      buildsrc:
        hostPath: /usr/src
        path: /usr/src
      debug:
        hostPath: /sys/kernel/debug
        path: /sys/kernel/debug
    commands:
      pre: echo "ulimit -l unlimited" >> /root/.bashrc
    command: "ulimit -l unlimited && ulimit -l && {{ if .Values.experiment.monitor_command }}{{ .Values.experiment.monitor_command }}{{ else }}python3 /opt/programs/ebpf_collect.py --nodes {{ .Values.experiment.nodes }} --start-indicator-file=/mnt/flux/start_ebpf_collection {{ if .Values.experiment.monitor_debug }}--debug{{ end }} --json {{ if .Values.experiment.monitor_target }}--include-pattern={{ .Values.experiment.monitor_target }}{{ end }} --stop-indicator-file=/mnt/flux/stop_ebpf_collection{{ end }} {{- range $index, $prog := $progs }} -p {{ $prog }} {{- end -}}"{{ end }}
{{- end }}

{{- define "chart.monitor_finish" -}}
         touch /mnt/flux/stop_ebpf_collection
{{- end }}

{{- define "chart.monitor_start" -}}
         echo "The parent process ID is: \$PPID"          
         echo "The execution parent process ID is: \$\$"         
         CGROUP_PATH_LINE=\$(cat "/proc/\$\$/cgroup")
         echo $CGROUP_PATH_LINE
         CGROUP_V2_PATH=\${CGROUP_PATH_LINE:3}
         ACTUAL_CGROUP_DIR="/sys/fs/cgroup\${CGROUP_V2_PATH}"
         TARGET_CGROUP_ID=\$(stat -c '%i' \$ACTUAL_CGROUP_DIR)
         echo "The cgroup id is \$TARGET_CGROUP_ID"
         echo -n \$TARGET_CGROUP_ID > /mnt/flux/cgroup-id.txt
         sleep 10
         flux exec -r all touch /mnt/flux/start_ebpf_collection
{{- end }}

{{/* Flux GPUs */}}
{{- define "chart.gpus" -}}
         {{ if .Values.minicluster.gpus }}procs=$(nproc); procs=$((procs - 1));   
         gpus={{ .Values.minicluster.gpus }}; 
         if [[ "$gpus" == "1" ]]; then
             gpus=0;
         else
             gpus=$((gpus - 1)); gpus=0-$gpus
         fi
         {{ $gpus := (.Values.minicluster.gpus | int) }}
         flux R encode --hosts=${hosts} --cores=0-${procs} --gpu=${gpus} > ${viewroot}/etc/flux/system/R
         cat ${viewroot}/etc/flux/system/R || true
         export CUDA_VISIBLE_DEVICES=0{{ range untilStep 1 $gpus 1 }},{{ . }}{{ end }}{{ end }}
{{- end }}

{{/* Flux Post */}}
{{- define "chart.fluxpost" -}}
         {{- if .Values.minicluster.commands_post }}{{- range $k, $v := .Values.minicluster.commands_post }}
           {{ . | toYaml | indent 4 | trim }}
         {{- end }}{{- end }}
{{- end }}

{{/* Flux Commands Finish */}}
{{- define "chart.fluxfinish" -}}
        {{- if .Values.minicluster.commands_finish }}{{- range $k, $v := .Values.minicluster.commands_finish }}
          {{ . | toYaml | indent 4 | trim }}
        {{- end }}{{- end }}
{{- end }}

{{/* Flux Save Logs */}}
{{- define "chart.savelogs" -}}
         {{- if .Values.minicluster.save_logs }}
         output=./results/\${app}
         (apt-get update {{ if .Values.logging.quiet }}> /dev/null 2>&1{{ end }} && apt-get install -y jq {{ if .Values.logging.quiet }}> /dev/null 2>&1{{ end }}) || (yum update -y {{ if .Values.logging.quiet }}> /dev/null 2>&1{{ end }} && yum install -y jq {{ if .Values.logging.quiet }}> /dev/null 2>&1{{ end }})
         mkdir -p \$output
         for jobid in \$(flux jobs -a --json | jq -r .jobs[].id); do
             echo
             study_id=\$(flux job info \$jobid jobspec | jq -r ".attributes.user.study_id")
             echo "FLUX-JOB START \${jobid} \${study_id}"
             echo "FLUX-JOB-JOBSPEC START"
             flux job info \$jobid jobspec
             echo "FLUX-JOB-JOBSPEC END" 
             {{ if .Values.minicluster.show_logs }}echo "FLUX-JOB-LOG START"
             flux job attach \$jobid
             echo "FLUX-JOB-LOG END"{{ end }}
             echo "FLUX-JOB-RESOURCES START"
             flux job info \${jobid} R
             echo "FLUX-JOB-RESOURCES END"
             echo "FLUX-JOB-EVENTLOG START" 
             flux job info \$jobid guest.exec.eventlog
             echo "FLUX-JOB-EVENTLOG END" 
             echo "FLUX-JOB END \${jobid} \${study_id}"
         done
         echo "FLUX JOB STATS"
         flux job stats         
         {{ if .Values.minicluster.sleep }}sleep infinity{{- end}}         
         {{- end }}
{{- end }}

{{/* Selector labels */}}
{{- define "chart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Create the name of the service account to use */}}
{{- define "chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "chart.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
