#ifndef _IPV6_HELPERS_H
#define _IPV6_HELPERS_H

static __always_inline bool my_ipv6_addr_cmp(const struct in6_addr *a1,
					     const struct in6_addr *a2)
{
	return a1->s6_addr32[0] == a2->s6_addr32[0] &&
	       a1->s6_addr32[1] == a2->s6_addr32[1] &&
	       a1->s6_addr32[2] == a2->s6_addr32[2] &&
	       a1->s6_addr32[3] == a2->s6_addr32[3];
}

static __always_inline bool ipv6_any(const struct in6_addr *a1)
{
	struct in6_addr a2 = {};

	return my_ipv6_addr_cmp(a1, &a2);
}

#endif
