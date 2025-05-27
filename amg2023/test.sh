#!/bin/bash

helm install --set experiment.tasks=2 --set amg.problem_size="1 1 1" --set amg.processor_topology="1 1 1" amg ./amg-2023

