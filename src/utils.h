#pragma once

int read_int_from_file(const char *path);
int write_str_to_file(const char *path, const char *val);
void hexdump(const void *buf, size_t len);
