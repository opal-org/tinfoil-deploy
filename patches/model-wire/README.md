# Fixed model envelopes

The measured model configuration adds a small gateway inside each model enclave. It decodes fixed-size request bodies before forwarding the unchanged JSON to the original engine, and frames the original engine response before it leaves the enclave. The gateway uses a closed internal network. The existing authenticated inference endpoints remain authenticated; `/opal-wire-status` is also authenticated and returns only aggregate counters.

Original model images, wrapped weights, engine commands and current allocations (4 vCPUs, 64 GiB, one B200 per model) are preserved. The earlier checked-in 16-vCPU settings do not describe the running allocation.

`provenance.json` pins the four source files, Python base and published image. Build on an assigned GCP worker using `docker build --build-arg PYTHON_BASE=<base_image from provenance.json> .`; never build on the orchestration controller. No credentials or private prompts are included in this directory. The production gateway emits no per-request payload diagnostics to stdout.

Local TLS fixture qualification is recorded separately from live TDX verification and real-model qualification. A timeout stops the caller waiting; it does not prove that GPU work or a controller mutation was cancelled. An ambiguous timeout requires demonstrated engine quiescence or a controlled restart and fresh verification before a later timed window.
