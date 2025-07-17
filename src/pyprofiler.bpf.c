#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>

// Python 3.10 type definitions
struct PyTypeObject {
	char _[24]; // Unused padding fields
	char *tp_name; // Type name
};

struct PyObject {
	char _[8]; // Unused padding fields
	struct PyTypeObject *ob_type;
};

struct PyVarObject {
	struct PyObject ob_base;
	char _[8]; // Unused padding fields
};

struct _PyStr {
	char _[48]; // Unused padding fields
	char buf[100]; // String content
};

struct PyCodeObject {
	char _[104]; // Unused padding fields
	struct _PyStr *co_filename;
	struct _PyStr *co_name;
};

struct PyFrameObject {
	struct PyVarObject ob_base;
	struct PyFrameObject *f_back;
	struct PyCodeObject *f_code;
};

// Stack frame information structure
struct stack_frame_info {
	char filename[100];
	char funcname[100];
};

// Add timestamp field in nanoseconds
struct stack_trace {
    __u32 pid;
    __u32 num_frames;
    __u64 timestamp_ns;   // New: kernel sampling timestamp
    struct stack_frame_info frames[20];
};

// BPF map for storing stack information
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

// Filtered PID map
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1);
} filter_pid SEC(".maps");

// Per-CPU map for storing stack trace data
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct stack_trace));
	__uint(max_entries, 1);
} stack_traces SEC(".maps");

SEC("perf_event")
int python_stack_trace(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tgid = (__u32)pid_tgid;

	// Get filtered PID
	int key = 0;
	int *target_pid = bpf_map_lookup_elem(&filter_pid, &key);
	if (!target_pid || *target_pid != tgid)
		return 0;

	// Get stack pointer
	void *sp = (void *)PT_REGS_SP(ctx);
	struct PyFrameObject *frame = NULL;
	unsigned long i = 0;

	// Search for PyFrameObject pointer in the stack
	for (i = 0; i < 200 && !frame; i++) {
		void **addr = (void **)(sp + i * sizeof(void *));
		void *potential_frame = NULL;

		// Safely read memory
		bpf_probe_read(&potential_frame, sizeof(potential_frame), addr);
		if (!potential_frame)
			continue;

		// Try to verify if it's a PyFrameObject
		struct PyObject *obj = (struct PyObject *)potential_frame;
		struct PyTypeObject *type = NULL;

		// Read object type
		if (bpf_probe_read(&type, sizeof(type), &obj->ob_type))
			continue;
		if (!type)
			continue;

		// Read type name
		char *tp_name = NULL;
		if (bpf_probe_read(&tp_name, sizeof(tp_name), &type->tp_name))
			continue;
		if (!tp_name)
			continue;

		// Read first 5 characters of type name
		char t0, t1, t2, t3, t4;

		bpf_probe_read(&t0, sizeof(t0), tp_name);
		bpf_probe_read(&t1, sizeof(t1), tp_name + 1);
		bpf_probe_read(&t2, sizeof(t2), tp_name + 2);
		bpf_probe_read(&t3, sizeof(t3), tp_name + 3);
		bpf_probe_read(&t4, sizeof(t4), tp_name + 4);

		if (t0 == 'f' && t1 == 'r' && t2 == 'a' && t3 == 'm' && t4 == 'e') {
			frame = (struct PyFrameObject *)potential_frame;
		}
	}

	// Return if PyFrameObject not found
	if (!frame)
		return 0;

	// Get stack trace structure from per-CPU map
	int zero = 0;
	struct stack_trace *trace = bpf_map_lookup_elem(&stack_traces, &zero);
	if (!trace)
		return 0;

	// Collect timestamp
    trace->timestamp_ns = bpf_ktime_get_ns();

	// Manually initialize structure
	trace->pid = tgid;
	trace->num_frames = 0;

// Since we cannot use memset, we need to ensure at least the frames to be used are initialized to 0
#pragma unroll
	for (i = 0; i < 20; i++) {
		trace->frames[i].filename[0] = 0;
		trace->frames[i].funcname[0] = 0;
	}

	// Collect stack information, maximum 20 stack frames
	struct PyFrameObject *current_frame = frame;
	for (i = 0; i < 20 && current_frame; i++) {
		struct PyCodeObject *code = NULL;

		// Read code object
		if (bpf_probe_read(&code, sizeof(code), &current_frame->f_code))
			break;
		if (!code)
			break;

		// Read filename
		struct _PyStr *filename = NULL;
		if (bpf_probe_read(&filename, sizeof(filename), &code->co_filename) == 0 &&
		    filename) {
			bpf_probe_read_str(trace->frames[i].filename,
					   sizeof(trace->frames[i].filename), filename->buf);
		}

		// Read function name
		struct _PyStr *funcname = NULL;
		if (bpf_probe_read(&funcname, sizeof(funcname), &code->co_name) == 0 && funcname) {
			bpf_probe_read_str(trace->frames[i].funcname,
					   sizeof(trace->frames[i].funcname), funcname->buf);
		}

		// Update stack frame count
		trace->num_frames++;

		// Get previous stack frame
		struct PyFrameObject *prev_frame = NULL;
		if (bpf_probe_read(&prev_frame, sizeof(prev_frame), &current_frame->f_back))
			break;

		current_frame = prev_frame;
		if (!current_frame)
			break;
	}

	// Send data to user space
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, trace, sizeof(*trace));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
