// started from code written by chatgpt

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define _GNU_SOURCE
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "uprobes.h"
#include "utils.h"
#include "perf_events.h"

int uprobe_event_type(void)
{
	static int uprobe_type = -1;
	static bool checked = false;

	if (checked)
		return uprobe_type;

	uprobe_type = read_int_from_file("/sys/bus/event_source/devices/uprobe/type");
	if (uprobe_type != -1)
		checked = true;

	return uprobe_type;
}

static void * map_file_ro(const char *path, size_t *size_out)
{
	struct stat st;
	void *p;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror(path);
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		close(fd);
		return NULL;
	}

	p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}

	*size_out = (size_t)st.st_size;
	return p;
}

/*
 * Return st_value for symbol in ET_DYN/ET_EXEC file.
 * For a shared library like libc.so, this is the offset you usually want
 * for a uprobe attached to PATH:OFFSET.
 */
static int
find_dynsym_value_elf64(const char *path, const char *symname, uint64_t *value_out)
{
	Elf64_Shdr *dynsym = NULL, *dynstr = NULL, *symtab = NULL, *strtab = NULL;
	size_t nsyms, sz = 0;
	Elf64_Sym *syms;
	Elf64_Shdr *shdrs;
	const char *strs;
	Elf64_Ehdr *eh;
	uint8_t *base;
	int rc = 0, i;

	base = map_file_ro(path, &sz);
	if (!base)
		return -1;

	if (sz < sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "file too small: %s\n", path);
		goto err_out;
	}

	eh = (Elf64_Ehdr *)base;
	if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
		eh->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "unsupported ELF: %s\n", path);
		goto err_out;
	}

	if (eh->e_shoff == 0 || eh->e_shentsize != sizeof(Elf64_Shdr)) {
		fprintf(stderr, "missing/invalid section table: %s\n", path);
		goto err_out;
	}

	shdrs = (Elf64_Shdr *)(base + eh->e_shoff);
	if ((uint8_t *)(shdrs + eh->e_shnum) > base + sz) {
		fprintf(stderr, "corrupt section table: %s\n", path);
		goto err_out;
	}

	for (i = 0; i < eh->e_shnum; i++) {
		if (shdrs[i].sh_type == SHT_DYNSYM) {
			dynsym = &shdrs[i];
			if (dynsym->sh_link < eh->e_shnum) {
			    dynstr = &shdrs[dynsym->sh_link];
			}
		} else if (shdrs[i].sh_type == SHT_SYMTAB) {
			symtab = &shdrs[i];
			if (symtab->sh_link < eh->e_shnum) {
			    strtab = &shdrs[symtab->sh_link];
			}
		}
	}

	// Prefer .dynsym for shared libs, then fall back to .symtab.
	Elf64_Shdr *symsec = dynsym ? dynsym : symtab;
	Elf64_Shdr *strsec = dynsym ? dynstr : strtab;
	if (!symsec || !strsec) {
		fprintf(stderr, "no symbol table found: %s\n", path);
		goto err_out;
	}

	if (symsec->sh_offset + symsec->sh_size > sz ||
		strsec->sh_offset + strsec->sh_size > sz) {
		fprintf(stderr, "corrupt symbol/string section: %s\n", path);
		goto err_out;
	}

	syms = (Elf64_Sym *)(base + symsec->sh_offset);
	strs = (const char *)(base + strsec->sh_offset);
	nsyms = symsec->sh_size / sizeof(Elf64_Sym);

	for (i = 0; i < nsyms; i++) {
		const char *name;

		if (syms[i].st_name >= strsec->sh_size)
			continue;

		name = strs + syms[i].st_name;
		if (strcmp(name, symname) == 0) {
			*value_out = syms[i].st_value;
			goto out;
		}
	}

err_out:
	rc = -1;
	fprintf(stderr, "symbol not found: %s in %s\n", symname, path);
out:
	munmap(base, sz);
	return rc;
}

int uprobe_init(struct bpf_object *obj, struct uprobe_data *probes,
		unsigned int count)
{
	struct bpf_program *prog;
	int prog_fd, rc = 0;
	unsigned int i;

	for (i = 0; i < count; ++i) {
		uint64_t probe_off = 0;

		if (find_dynsym_value_elf64(probes[i].path, probes[i].func,
					    &probe_off) < 0) {
			fprintf(stderr, "Failed to find function '%s' in '%s'\n",
				probes[i].func, probes[i].path);
			rc = 1;
			continue;
		}

		prog = bpf_object__find_program_by_name(obj, probes[i].prog);
		if (!prog) {
			fprintf(stderr,
				"%s: Failed to get prog \"%s\" in obj file\n",
				__func__, probes[i].prog);
			rc = 1;
			continue;
		}
		prog_fd = bpf_program__fd(prog);

		probes[i].fd = uprobe_perf_event(prog_fd, probes[i].path, probe_off,
						 probes[i].retprobe);
		if (probes[i].fd < 0) {
			fprintf(stderr,
				"Failed to create perf_event on %s\n",
				probes[i].func);
			rc = 1;
		}
	}

	return rc;
}

void uprobe_cleanup(struct uprobe_data *probes, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; ++i) {
		if (probes[i].fd < 0)
			continue;

		ioctl(probes[i].fd, PERF_EVENT_IOC_DISABLE, 0);
		close(probes[i].fd);
	}
}
