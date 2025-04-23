# IOR

```console
Synopsis ior

Flags
  -c, --collective              Use collective I/O
  -C                            reorderTasks -- changes task ordering for readback (useful to avoid client cache)
  -e                            fsync -- perform a fsync() operation at the end of each read/write phase
  -E                            useExistingTestFile -- do not remove test file before write access
  -F                            filePerProc -- file-per-process
  -g                            intraTestBarriers -- use barriers between open, write/read, and close
  -k                            keepFile -- don't remove the test file(s) on program exit
  -K                            keepFileWithError  -- keep error-filled file(s) after data-checking
  -m                            multiFile -- use number of reps (-i) for multiple file count
  -r                            readFile -- read existing file
  -R                            checkRead -- verify that the output of read matches the expected signature (used with -G)
  -u                            uniqueDir -- use unique directory name for each file-per-process
  -v                            verbose -- output information (repeating flag increases level)
  -w                            writeFile -- write file
  -W                            checkWrite -- check read after write
  -x                            singleXferAttempt -- do not retry transfer if incomplete
  -y                            dualMount -- use dual mount points for a filesystem
  -Y                            fsyncPerWrite -- perform sync operation after every write operation
  -z                            randomOffset -- access is to random, not sequential, offsets within a file
  -Z                            reorderTasksRandom -- changes task ordering to random ordering for readback
  --warningAsErrors             Any warning should lead to an error.
  --dryRun                      do not perform any I/Os just run evtl. inputs print dummy output

Optional arguments
  -a=POSIX                      API for I/O [POSIX|PMDK|DUMMY|MPIIO|NCMPI|MMAP|CEPHFS|Gfarm]
  -A=0                          refNum -- user supplied reference number to include in the summary
  -b=1048576                    blockSize -- contiguous bytes to write per task  (e.g.: 8, 4k, 2m, 1g)
  -d=0                          interTestDelay -- delay between reps in seconds
  -D=0                          deadlineForStonewalling -- seconds before stopping write or read phase
  -O stoneWallingWearOut=1           -- once the stonewalling timeout is over, all process finish to access the amount of data
  -O stoneWallingWearOutIterations=N -- stop after processing this number of iterations, needed for reading data back written with stoneWallingWearOut
  -O stoneWallingStatusFile=FILE     -- this file keeps the number of iterations from stonewalling during write and allows to use them for read
  -O minTimeDuration=0           -- minimum Runtime for the run (will repeat from beginning of the file if time is not yet over)
  -f=STRING                     scriptFile -- test script name
  -G=0                          setTimeStampSignature -- set value for time stamp signature/random seed
  -i=1                          repetitions -- number of repetitions of test
  -j=0                          outlierThreshold -- warn on outlier N seconds from mean
  -l, --dataPacketType=STRING   datapacket type-- type of packet that will be created [offset|incompressible|timestamp|random|o|i|t|r]
  -M=STRING                     memoryPerNode -- hog memory on the node  (e.g.: 2g, 75%)
  -N=-1                         numTasks -- number of tasks that are participating in the test (overrides MPI)
  -o=testFile                   testFile -- full name for test
  -O=STRING                     string of IOR directives (e.g. -O checkRead=1,GPUid=2)
  -Q=1                          taskPerNodeOffset for read tests use with -C & -Z options (-C constant N, -Z at least N)
  -s=1                          segmentCount -- number of segments
  -t=262144                     transferSize -- size of transfer in bytes (e.g.: 8, 4k, 2m, 1g)
  -T=0                          maxTimeDuration -- max time in minutes executing repeated test; it aborts only between iterations and not within a test!
  -X=0                          reorderTasksRandomSeed -- random seed for -Z option
  --randomPrefill=0             For random -z access only: Prefill the file with this blocksize, e.g., 2m
  --random-offset-seed=-1       The seed for -z
  -O summaryFile=FILE                 -- store result data into this file
  -O summaryFormat=[default,JSON,CSV] -- use the format for outputting the summary
  -O saveRankPerformanceDetailsCSV=<FILE> -- store the performance of each rank into the named CSV file.


Module POSIX

Flags
  --posix.odirect               Direct I/O Mode
  --posix.rangelocks            Use range locks (read locks for read ops)


Module PMDK


Module DUMMY

Flags
  --dummy.delay-only-rank0      Delay only Rank0

Optional arguments
  --dummy.delay-create=0        Delay per create in usec
  --dummy.delay-close=0         Delay per close in usec
  --dummy.delay-sync=0          Delay for sync in usec
  --dummy.delay-xfer=0          Delay per xfer in usec


Module MPIIO

Flags
  --mpiio.showHints             Show MPI hints
  --mpiio.preallocate           Preallocate file size
  --mpiio.useStridedDatatype    put strided access into datatype
  --mpiio.useFileView           Use MPI_File_set_view

Optional arguments
  --mpiio.hintsFileName=STRING  Full name for hints file


Module NCMPI

Flags
  --ncmpi.showHints             Show MPI hints
  --ncmpi.preallocate           Preallocate file size
  --ncmpi.useStridedDatatype    put strided access into datatype
  --ncmpi.useFileView           Use MPI_File_set_view

Optional arguments
  --ncmpi.hintsFileName=STRING  Full name for hints file


Module MMAP

Flags
  --mmap.madv_dont_need         Use advise don't need
  --mmap.madv_pattern           Use advise to indicate the pattern random/sequential


Module CEPHFS

Flags
  --cephfs.olazy                Enable Lazy I/O

Optional arguments
  --cephfs.user=STRING          Username for the ceph cluster
  --cephfs.conf=STRING          Config file for the ceph cluster
  --cephfs.prefix=STRING        Mount prefix
  --cephfs.remote_prefix=STRING Remote mount prefix
```
