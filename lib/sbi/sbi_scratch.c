 /*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include <sbi/riscv_locks.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hartmask.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_string.h>

u32 last_hartid_having_scratch = SBI_HARTMASK_MAX_BITS - 1;
struct sbi_scratch *hartid_to_scratch_table[SBI_HARTMASK_MAX_BITS] = { 0 };

static spinlock_t extra_lock = SPIN_LOCK_INITIALIZER;
static unsigned int first_free;

typedef struct sbi_scratch *(*hartid2scratch)(ulong hartid, ulong hartindex);

/**
 * sbi_scratch_init() - initialize scratch table and allocator
 *
 * @scratch:	pointer to table
 * Return:	0 on success
 */
int sbi_scratch_init(struct sbi_scratch *scratch)
{
	u32 i;
	const struct sbi_platform *plat = sbi_platform_ptr(scratch);

	for (i = 0; i < SBI_HARTMASK_MAX_BITS; i++) {
		if (sbi_platform_hart_invalid(plat, i))
			continue;
		hartid_to_scratch_table[i] =
			((hartid2scratch)scratch->hartid_to_scratch)(i,
					sbi_platform_hart_index(plat, i));
		if (hartid_to_scratch_table[i])
			last_hartid_having_scratch = i;
	}

	/* Initialize memory allocation block list */
	scratch = sbi_hartid_to_scratch(last_hartid_having_scratch);

	scratch->mem.prev_size = (2 * sizeof(unsigned int)) | 1U;
	scratch->mem.size = SBI_SCRATCH_SIZE -
			    offsetof(struct sbi_scratch, mem.mem);
	first_free = offsetof(struct sbi_scratch, mem);
	scratch->mem.prev = 0;
	scratch->mem.next = 0;

	return 0;
}

/**
 * sbi_scratch_alloc_offset() - allocate scratch memory
 *
 * @size:	requested size
 * Return:	offset of allocated block on succcess, 0 on failure
 */
unsigned long sbi_scratch_alloc_offset(unsigned long size)
{
	unsigned long ret;
	unsigned int best_size = ~0U;
	struct sbi_scratch_alloc *best = NULL;
	struct sbi_scratch *scratch =
		sbi_hartid_to_scratch(last_hartid_having_scratch);
	unsigned int next;
	struct sbi_scratch_alloc *current;
	struct sbi_scratch_alloc *pred, *succ;
	struct sbi_scratch_alloc *end =
		(void *)((char *)scratch + SBI_SCRATCH_SIZE);

	/*
	 * When allocating zero bytes we still need space
	 * for the prev and next fields.
	 */
	if (!size)
		size = 1;
	size = ALIGN(size, 2 * sizeof(unsigned int));

	spin_lock(&extra_lock);

	/* Find best fitting free block */
	for (next = first_free; next; next = current->next) {
		current = (void *)((char *)scratch + next);
		if (current->size > best_size || current->size < size)
			continue;
		best_size = current->size;
		best = current;
	}
	if (!best) {
		spin_unlock(&extra_lock);
		return 0;
	}

	/* Update free list */
	if (best->prev)
		pred = (void *)((char *)scratch + best->prev);
	else
		pred = NULL;
	if (best->next)
		succ = (void *)((char *)scratch + best->next);
	else
		succ = NULL;

	if (best->size > size + SBI_SCRATCH_ALLOC_SIZE) {
		/* Split block, use the lower part for allocation. */
		current = (struct sbi_scratch_alloc *)&best->mem[size];
		next = (char *)current - (char *)scratch;
		current->size = best->size - size -
				SBI_SCRATCH_ALLOC_SIZE;
		current->prev = best->prev;
		current->next = best->next;
		current->prev_size = size | 1U;
		best->size = size;
		if (succ)
			succ->prev = next;
	} else {
		next = best->next;
		if (succ)
			succ->prev = best->prev;
		current = best;
	}

	if (pred)
		pred->next = next;
	else
		first_free = next;

	/* Update memory block list */
	succ = (struct sbi_scratch_alloc *)&current->mem[current->size];

	best->size |= 1U;

	if (succ < end)
		succ->prev_size = current->size;

	ret =  best->mem - (unsigned char *)scratch;

	/* Erase allocated scratch memory */
	for (unsigned int i = 0; i <= last_hartid_having_scratch; i++) {
		void *ptr;
		struct sbi_scratch *rscratch;

		rscratch = sbi_hartid_to_scratch(i);
		if (!rscratch)
			continue;
		ptr = sbi_scratch_offset_ptr(rscratch, ret);
		sbi_memset(ptr, 0, size);
	}

	spin_unlock(&extra_lock);

	return ret;
}

/**
 * sbi_scratch_free_offset() - free scratch memory
 *
 * @offset:	offset to memory to be freed
 */
void sbi_scratch_free_offset(unsigned long offset)
{
	struct sbi_scratch *scratch =
		sbi_hartid_to_scratch(last_hartid_having_scratch);
	struct sbi_scratch_alloc *freed = (void *)((unsigned char *)scratch +
				      offset - SBI_SCRATCH_ALLOC_SIZE);
	struct sbi_scratch_alloc *pred, *succ;
	struct sbi_scratch_alloc *end =
		(void *)((char *)scratch + SBI_SCRATCH_SIZE);

	spin_lock(&extra_lock);

	if (!offset || !(freed->size & 1U)) {
		spin_unlock(&extra_lock);
		return;
	}

	/* Mark block as free */
	freed->size &= ~1U;

	pred = (struct sbi_scratch_alloc *)((char *)freed -
	       (freed->prev_size & ~1U) - SBI_SCRATCH_ALLOC_SIZE);
	if (pred >= &scratch->mem && !(pred->size & 1U)) {
		/* Coalesce free blocks */
		pred->size += freed->size + SBI_SCRATCH_ALLOC_SIZE;
		freed = pred;
	} else {
		/* Insert at start of free list */
		if (first_free) {
			succ = (void *)((char *)scratch + first_free);
			succ->prev = offset - SBI_SCRATCH_ALLOC_SIZE;
		}
		freed->next = first_free;
		freed->prev = 0;
		first_free = offset - SBI_SCRATCH_ALLOC_SIZE;
	}

	succ = (struct sbi_scratch_alloc *)&freed->mem[freed->size & ~1U];
	if (succ < end) {
		if (!(succ->size & 1U)) {
			struct sbi_scratch_alloc *succ2;

			/* Coalesce free blocks */
			succ2 = (struct sbi_scratch_alloc *)
				&succ->mem[succ->size & ~1U];
			freed->size += SBI_SCRATCH_ALLOC_SIZE + succ->size;
			if (succ2 < end)
				succ2->prev_size = freed->size;

			/* Remove successor from free list */
			if (succ->prev) {
				pred = (void *)((char *)scratch + succ->prev);
				pred->next = succ->next;
			} else {
				first_free = succ->next;
			}
			if (succ->next) {
				succ2 = (void *)((char *)scratch + succ->next);
				succ2->prev = succ->prev;
			}
		} else {
			succ->prev_size = freed->size;
		}
	}
	spin_unlock(&extra_lock);
}
