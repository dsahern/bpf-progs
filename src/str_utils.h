/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STR_UTILS_H
#define __STR_UTILS_H

int str_to_int(const char *str, int min, int max, int *value);
int str_to_ushort(const char *str, unsigned short *us);
int str_to_ulong(const char *str, unsigned long *ul);
int str_to_ulong_base(const char *str, unsigned long *ul, int base);
int str_to_ullong(const char *str, unsigned long long *ul);
int str_to_mac(const char *str, unsigned char *mac);
int get_ifidx(const char *arg);

int parsestr(char *str, char *delims, char *fields[], int nmax);
void print_mac(const __u8 *mac, bool reverse);
#endif
