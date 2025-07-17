#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <getopt.h> // Add getopt support for command line arguments

#include "pyprofiler.skel.h"

// Stack frame information structure
struct stack_frame_info {
	char filename[100];
	char funcname[100];
};

// Stack trace data structure
struct stack_trace {
	__u32 pid;
	__u32 num_frames;
	__u64 timestamp_ns; // New field
	struct stack_frame_info frames[20]; // Maximum 20 stack frames
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static FILE *output_file = NULL; // Output file
static int output_format = 0; // 0=standard output, 1=structured output

static void sig_handler(int sig)
{
	exiting = true;
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd,
			   unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_size)
{
	struct stack_trace *trace = (struct stack_trace *)data;

	if (output_format == 0) {
		// Standard human-readable output
		fprintf(output_file, "EVENT\n");
		fprintf(output_file, "timestamp=%llu\n", (unsigned long long)trace->timestamp_ns);
		fprintf(output_file, "pid=%u\n", trace->pid);
		fprintf(output_file, "frames=%u\n", trace->num_frames);

		for (int i = 0; i < trace->num_frames; i++) {
			fprintf(output_file, "frame%d=%s:%s\n", i, trace->frames[i].filename,
				trace->frames[i].funcname);
		}
		fprintf(output_file, "END\n\n");
	} else {
		// Structured output, easier to parse
		fprintf(output_file, "EVENT|%llu|%u|%u", (unsigned long long)trace->timestamp_ns,
			trace->pid, trace->num_frames);

		for (int i = 0; i < trace->num_frames; i++) {
			fprintf(output_file, "|%s:%s", trace->frames[i].filename,
				trace->frames[i].funcname);
		}
		fprintf(output_file, "\n");
	}

	// Ensure output is immediately written to file, so data is preserved even if program crashes
	fflush(output_file);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] PID\n"
		"Trace Python stack frames for the specified PID\n"
		"\n"
		"Options:\n"
		"  -h, --help           Display this help message\n"
		"  -o, --output FILE    Write output to FILE instead of stdout\n"
		"  -f, --format FORMAT  Output format (0=standard, 1=structured, default: 0)\n"
		"  -r, --rate RATE      Sampling rate in Hz (default: 99)\n",
		prog);
}

int main(int argc, char **argv)
{
	struct pyprofiler_bpf *skel;
	struct perf_event_attr attr = {};
	int perf_fd, err, i;
	struct perf_buffer *pb = NULL;
	struct bpf_link **links = NULL;
	int target_pid = -1;
	int sample_freq = 99; // Default sampling rate
	char *output_path = NULL;

	// Define long options
	static struct option long_options[] = { { "help", no_argument, 0, 'h' },
						{ "output", required_argument, 0, 'o' },
						{ "format", required_argument, 0, 'f' },
						{ "rate", required_argument, 0, 'r' },
						{ 0, 0, 0, 0 } };

	// Parse command line arguments
	int option_index = 0;
	int opt;

	while ((opt = getopt_long(argc, argv, "ho:f:r:", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'o':
			output_path = optarg;
			break;
		case 'f':
			output_format = atoi(optarg);
			if (output_format < 0 || output_format > 1) {
				fprintf(stderr, "Invalid format: %d (must be 0 or 1)\n",
					output_format);
				return 1;
			}
			break;
		case 'r':
			sample_freq = atoi(optarg);
			if (sample_freq <= 0) {
				fprintf(stderr, "Invalid sampling rate: %d\n", sample_freq);
				return 1;
			}
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	// Check if remaining arguments contain PID
	if (optind >= argc) {
		fprintf(stderr, "Error: PID argument is required\n");
		print_usage(argv[0]);
		return 1;
	}

	target_pid = atoi(argv[optind]);
	if (target_pid <= 0) {
		fprintf(stderr, "Invalid PID: %d\n", target_pid);
		return 1;
	}

	// Set output file
	if (output_path) {
		output_file = fopen(output_path, "w");
		if (!output_file) {
			perror("Failed to open output file");
			return 1;
		}
	} else {
		output_file = stdout;
	}

	// Write metadata header
	if (output_format == 0) {
		fprintf(output_file, "# Python Stack Trace Data\n");
		fprintf(output_file, "# Target PID: %d\n", target_pid);
		fprintf(output_file, "# Sampling Rate: %d Hz\n", sample_freq);
		fprintf(output_file, "# Format: Standard\n\n");
	} else {
		fprintf(output_file, "FORMAT|1.0\n");
		fprintf(output_file, "METADATA|pid=%d|rate=%d\n", target_pid, sample_freq);
		fprintf(output_file, "HEADER|timestamp|pid|frame_count|[frames...]\n");
	}

	// Set higher resource limits
	struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &rlim);

	// Set libbpf log callback
	libbpf_set_print(libbpf_print_fn);

	// Open BPF application
	skel = pyprofiler_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Load and verify BPF program
	err = pyprofiler_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// Write target PID to BPF map
	int key = 0;
	int map_fd = bpf_map__fd(skel->maps.filter_pid);
	err = bpf_map_update_elem(map_fd, &key, &target_pid, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update filter_pid map: %d\n", err);
		goto cleanup;
	}

	// Set signal handling
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Set performance event attributes
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.sample_period = 0; // Use freq instead of period
	attr.sample_freq = sample_freq;
	attr.freq = 1;

	// Get available CPU count
	int ncpus = libbpf_num_possible_cpus();

	// Allocate memory for each CPU link
	links = calloc(ncpus, sizeof(*links));
	if (!links) {
		fprintf(stderr, "Failed to allocate memory for links\n");
		err = -ENOMEM;
		goto cleanup;
	}

	// Create performance event and attach BPF program for each CPU
	for (i = 0; i < ncpus; i++) {
		// Sample globally, not a specific process
		perf_fd = perf_event_open(&attr, -1, i, -1, PERF_FLAG_FD_CLOEXEC);
		if (perf_fd < 0) {
			err = -errno;
			perror("perf_event_open");
			goto cleanup;
		}

		// Use the latest API version
		links[i] = bpf_program__attach_perf_event(skel->progs.python_stack_trace, perf_fd);
		if (!links[i]) {
			err = -errno;
			fprintf(stderr, "Failed to attach BPF program to perf event: %d\n", err);
			close(perf_fd);
			goto cleanup;
		}
	}

	// Set performance buffer
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8 /* page count */, handle_event,
			      handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	fprintf(stderr, "Tracing Python stack for PID %d at %d Hz... Press Ctrl+C to exit.\n",
		target_pid, sample_freq);

	// Main loop
	while (!exiting) {
		err = perf_buffer__poll(pb, 100 /* timeout in milliseconds */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	// Release all resources
	perf_buffer__free(pb);

	// Clean up BPF links
	if (links) {
		for (i = 0; i < ncpus; i++) {
			if (links[i])
				bpf_link__destroy(links[i]);
		}
		free(links);
	}

	pyprofiler_bpf__destroy(skel);

	// Close output file
	if (output_file && output_file != stdout) {
		fclose(output_file);
	}

	return err < 0 ? -err : 0;
}
