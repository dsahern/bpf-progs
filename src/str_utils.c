// SPDX-License-Identifier: GPL-2.0
/*
 * String conversion and parsing functions.
 *
 * David Ahern <dsahern@gmail.com>
 */
#include <linux/if_ether.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "str_utils.h"

static int str_to_int_base(const char *str, int min, int max, int *value, int base)
{
	int number;
	char *end;

	errno = 0;
	number = (int) strtol(str, &end, base);

	if ( ((*end == '\0') || (*end == '\n')) && (end != str) &&
	    (errno != ERANGE) && (min <= number) && (number <= max)) {
		*value = number;
		return 0;
	}

	return -1;
}

int str_to_int(const char *str, int min, int max, int *value)
{
	return str_to_int_base(str, min, max, value, 0);
}

int str_to_ushort(const char *str, unsigned short *us)
{
	int i;

	if (str_to_int(str, 0, 0xFFFF, &i) != 0)
		return -1;

	*us = (unsigned short) (i);

	return 0;
}

int str_to_ulong_base(const char *str, unsigned long *ul, int base)
{
	char *end;

	*ul= strtoul(str, &end, base);
	if (*end != '\0')
		return -1;

	return 0;
}

int str_to_ulong(const char *str, unsigned long *ul)
{
	return str_to_ulong_base(str, ul, 0);
}

int str_to_ullong(const char *str, unsigned long long *ul)
{
	char *end;

	*ul= strtoull(str, &end, 0);
	if (*end != '\0') 
		return -1;

	return 0;
}

int str_to_mac(const char *str, unsigned char *mac)
{
	int rc = -1, m, i;
	char *s = strdup(str), *p, *d, tmp[3];

	if (!s)
		return -1;

	p = s;
	tmp[2] = '\0';
	for (i = 0; i < ETH_ALEN; ++i) {
		if (*p == '\0')
			goto out;

		d = strchr(p, ':');
		if (d) {
			*d = '\0';
			if (strlen(p) > 2)
				goto out;

			strcpy(tmp, p);
			p = d + 1;
		} else {
			strncpy(tmp, p, 2);
			p += 2;
		}
		
		if (str_to_int_base(tmp, 0, 0xFF, &m, 16) != 0)
			goto out;

		mac[i] = m;
	}

	if (*p == '\0')
		rc = 0;
out:
	free(s);

	return rc;
}

int get_ifidx(const char *arg)
{
	int idx;

	idx = if_nametoindex(arg);
	if (!idx)
		idx = strtoul(arg, NULL, 0);

	return idx;
}

/* find parameters in a string -- based on Harbison and Steele, p. 291 */
int parsestr(char *str, char *delims, char *fields[], int nmax)
{
	int n;

	if (!str || (*str == '\0'))
		return 0;

	n = 0;
	fields[0] = strtok(str, delims);
	while ((fields[n] != (char *) NULL) && (n < (nmax-1))) {
		++n;
		fields[n] = strtok(NULL, delims);
	}

	if ((n == (nmax - 1)) && (fields[n] != (char *) NULL))
		++n;

	return n;
}

void print_mac(const __u8 *mac, bool reverse)
{
	if (reverse)
		printf("%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
		       mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
	else
		printf("%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
