#ifndef _IPV6_HELPERS_H
#define _IPV6_HELPERS_H

static __always_inline bool do_ipv6_addr_cmp(const struct in6_addr *a1,
					     const struct in6_addr *a2)
{
	return a1->s6_addr32[0] == a2->s6_addr32[0] &&
	       a1->s6_addr32[1] == a2->s6_addr32[1] &&
	       a1->s6_addr32[2] == a2->s6_addr32[2] &&
	       a1->s6_addr32[3] == a2->s6_addr32[3];
}

static __always_inline bool ipv6_is_any(const struct in6_addr *a1)
{
	struct in6_addr a2 = {};

	return do_ipv6_addr_cmp(a1, &a2);
}

#endif
