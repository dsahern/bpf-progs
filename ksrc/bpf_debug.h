#ifndef _BPF_DEBUG_H
#define _BPF_DEBUG_H

#define bpf_debug(fmt, ...)					\
	{							\
		char __fmt[] = fmt;				\
		bpf_trace_printk(__fmt, sizeof(__fmt),		\
				 ##__VA_ARGS__);		\
	}

#endif
