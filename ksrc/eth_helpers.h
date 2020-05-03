static __always_inline bool mac_cmp(const unsigned char *mac1, const unsigned char *mac2)
{
	u32 a1 = *((u32 *)&mac1[0]);
	u32 a2 = *((u32 *)&mac2[0]);
	u16 b1 = *((u16 *)&mac1[4]);
	u16 b2 = *((u16 *)&mac2[4]);

	return a1 == a2 && b1 == b2;
}
