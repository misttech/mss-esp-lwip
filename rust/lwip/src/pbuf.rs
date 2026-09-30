// Copyright (c) 2001-2004 Swedish Institute of Computer Science.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
// SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
// OF SUCH DAMAGE.
//
// This file is part of the lwIP TCP/IP stack.
//
// Author: Adam Dunkels <adam@sics.se>
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! Packet buffer management, from `src/core/pbuf.c`.
//!
//! Packets are built from the pbuf data structure. It supports dynamic memory allocation
//! for packet contents or can reference externally managed packet contents both in RAM and
//! ROM. Quick allocation for incoming packets is provided through pools with fixed sized
//! pbufs.
//!
//! A packet may span over multiple pbufs, chained as a singly linked list. This is called
//! a "pbuf chain". Multiple packets may be queued, also using this singly linked list.
//! This is called a "packet queue". So, a packet queue consists of one or more pbuf
//! chains, each of which consist of one or more pbufs. CURRENTLY, PACKET QUEUES ARE NOT
//! SUPPORTED!!! Use helper structs to queue multiple packets. The differences between a
//! pbuf chain and a packet queue are very precise but subtle. The last pbuf of a packet
//! has a `->tot_len` field that equals the `->len` field. It can be found by traversing
//! the list. If the last pbuf of a packet has a `->next` field other than NULL, more
//! packets are on the queue. Therefore, looping through a pbuf of a single packet, has an
//! loop end condition (`tot_len == p->len`), NOT (`next == NULL`).
//!
//! # Safety
//!
//! Pbufs are shared with the C stack, which allocates, links, and frees them; every
//! function here takes them as the raw pointers C passes. Unless a function says
//! otherwise, each pbuf pointer it takes is null where the C function allows it, and
//! otherwise a live pbuf at the head of a well-formed chain: every `next` is null or
//! another live pbuf, each pbuf's `payload` is valid for its `len` bytes, and nothing else
//! uses the chain during the call except as lwIP's own locking allows. Payloads are read
//! and written through raw pointers, as in C, since the stack may alias them.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering::Relaxed};

use crate::config;
use crate::links::{mem_free, mem_malloc, mem_trim, memp_free, memp_malloc};
use crate::mem::{MemSize, mem_align, mem_align_size};
use crate::sys::locked;
use crate::types::*;

/// `SIZEOF_STRUCT_PBUF`: `struct pbuf`, aligned.
const SIZEOF_STRUCT_PBUF: usize = mem_align_size(core::mem::size_of::<Pbuf>());

/// Since the pool is created in memp, `PBUF_POOL_BUFSIZE` will be automatically aligned
/// there. Therefore, `PBUF_POOL_BUFSIZE_ALIGNED` can be used here.
const PBUF_POOL_BUFSIZE_ALIGNED: usize = mem_align_size(config::PBUF_POOL_BUFSIZE);

/// Set when `pbuf_alloc` found the pbuf pool empty and a call to free some out-of-sequence
/// TCP segments is queued; cleared when it runs (`volatile u8_t` in C).
#[cfg(pbuf_pool_free_ooseq)]
#[allow(non_upper_case_globals)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static pbuf_free_ooseq_pending: AtomicU8 = AtomicU8::new(0);

#[cfg(pbuf_pool_free_ooseq)]
unsafe extern "C" {
    /// The TCP PCBs in a state in which they accept or send data.
    static tcp_active_pcbs: *mut c_void;
    /// Free all ooseq pbufs (and possibly reset SACK state).
    fn tcp_free_ooseq(pcb: *mut c_void);
    /// Call a specific function in the thread context of tcpip_thread for easy access
    /// synchronization, without waiting if the queue is full.
    fn tcpip_try_callback(
        function: Option<unsafe extern "C" fn(ctx: *mut c_void)>,
        ctx: *mut c_void,
    ) -> ErrT;
}

/// Attempt to reclaim some memory from queued out-of-sequence TCP segments if we run out
/// of pool pbufs. It's better to give priority to new packets if we're running out.
///
/// This must be done in the correct thread context therefore this function can only be
/// used with `NO_SYS=0` and through tcpip_callback.
#[cfg(pbuf_pool_free_ooseq)]
fn pbuf_free_ooseq() {
    // SYS_ARCH_SET(pbuf_free_ooseq_pending, 0).
    locked(|| pbuf_free_ooseq_pending.store(0, Relaxed));

    // `struct tcp_pcb` is not mirrored until tcp.c is ported: its `next` and `ooseq` are
    // read at the offsets the configuration reports.
    // SAFETY: `tcp_active_pcbs` is the list TCP keeps in the tcpip thread this runs in;
    // each PCB on it is live, and `next` and `ooseq` are pointers at those offsets.
    unsafe {
        let mut pcb = ptr::addr_of!(tcp_active_pcbs).read();
        while !pcb.is_null() {
            let ooseq = pcb
                .byte_add(config::TCP_PCB_OOSEQ)
                .cast::<*mut c_void>()
                .read();
            if !ooseq.is_null() {
                // Free the ooseq pbufs of one PCB only.
                tcp_free_ooseq(pcb);
                return;
            }
            pcb = pcb
                .byte_add(config::TCP_PCB_NEXT)
                .cast::<*mut c_void>()
                .read();
        }
    }
}

/// Just a callback function for tcpip_callback() that calls `pbuf_free_ooseq()`.
#[cfg(pbuf_pool_free_ooseq)]
unsafe extern "C" fn pbuf_free_ooseq_callback(arg: *mut c_void) {
    let _ = arg;
    pbuf_free_ooseq();
}

/// Queue a call to `pbuf_free_ooseq` if not already queued.
#[cfg(pbuf_pool_free_ooseq)]
fn pbuf_pool_is_empty() {
    let queued = locked(|| {
        let queued = pbuf_free_ooseq_pending.load(Relaxed);
        pbuf_free_ooseq_pending.store(1, Relaxed);
        queued
    });

    if queued == 0 {
        // Queue a call to pbuf_free_ooseq if not already queued.
        // SAFETY: the callback takes no context and runs in the tcpip thread.
        if unsafe { tcpip_try_callback(Some(pbuf_free_ooseq_callback), ptr::null_mut()) } != ERR_OK
        {
            locked(|| pbuf_free_ooseq_pending.store(0, Relaxed));
        }
    }
}

/// `PBUF_POOL_IS_EMPTY()`: nothing to do without TCP out-of-sequence queueing.
#[cfg(not(pbuf_pool_free_ooseq))]
fn pbuf_pool_is_empty() {}

/// Initialize members of struct pbuf after allocation.
///
/// # Safety
///
/// `p` is writable for a `struct pbuf`.
unsafe fn pbuf_init_alloced_pbuf(
    p: *mut Pbuf,
    payload: *mut c_void,
    tot_len: u16,
    len: u16,
    type_: PbufType,
    flags: u8,
) {
    // SAFETY: writable, per the caller. Every field is written; LWIP_PBUF_CUSTOM_DATA_INIT
    // is empty.
    unsafe {
        p.write(Pbuf {
            next: None,
            payload,
            tot_len,
            len,
            type_internal: type_ as u8,
            flags,
            ref_: 1,
            if_idx: NETIF_NO_INDEX,
        });
    }
}

/// Allocates a pbuf of the given type (possibly a chain for `PBUF_POOL` type).
///
/// The actual memory allocated for the pbuf is determined by the layer at which the pbuf
/// is allocated and the requested size (from the size parameter).
///
/// `layer` is the header size, `length` the size of the pbuf's payload, and `type_` how
/// and where the pbuf should be allocated:
/// - `PBUF_RAM`: buffer memory for pbuf is allocated as one large chunk. This includes
///   protocol headers as well.
/// - `PBUF_ROM`: no buffer memory is allocated for the pbuf, even for protocol headers.
///   Additional headers must be prepended by allocating another pbuf and chain in to the
///   front of the ROM pbuf. It is assumed that the memory used is really similar to ROM
///   in that it is immutable and will not be changed. Memory which is dynamic should
///   generally not be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
/// - `PBUF_REF`: no buffer memory is allocated for the pbuf, even for protocol headers.
///   It is assumed that the pbuf is only being used in a single thread. If the pbuf gets
///   queued, then pbuf_take should be called to copy the buffer.
/// - `PBUF_POOL`: the pbuf is allocated as a pbuf chain, with pbufs from the pbuf pool
///   (`MEMP_PBUF_POOL`).
///
/// Returns the allocated pbuf. If multiple pbufs where allocated, this is the first pbuf
/// of a pbuf chain.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn pbuf_alloc(layer: PbufLayer, length: u16, type_: PbufType) -> *mut Pbuf {
    let mut offset = layer as u16;
    match type_ {
        // SAFETY: no payload yet; the caller sets one.
        PBUF_REF | PBUF_ROM => unsafe { pbuf_alloc_reference(ptr::null_mut(), length, type_) },
        PBUF_POOL => {
            let mut p: *mut Pbuf = ptr::null_mut();
            let mut last: *mut Pbuf = ptr::null_mut();
            let mut rem_len = length;
            loop {
                // SAFETY: a pool element, or null.
                let q = unsafe { memp_malloc(config::MEMP_PBUF_POOL) }.cast::<Pbuf>();
                if q.is_null() {
                    pbuf_pool_is_empty();
                    // Free chain so far allocated.
                    if !p.is_null() {
                        // SAFETY: the chain allocated so far is well formed.
                        unsafe { pbuf_free(p) };
                    }
                    // Bail out unsuccessfully.
                    return ptr::null_mut();
                }
                let room = PBUF_POOL_BUFSIZE_ALIGNED.wrapping_sub(mem_align_size(offset.into()));
                let qlen = rem_len.min(room as u16);
                // SAFETY: a pool element holds a struct pbuf and PBUF_POOL_BUFSIZE bytes
                // after it, which the payload starts in.
                unsafe {
                    let payload = mem_align(
                        q.cast::<u8>()
                            .wrapping_add(SIZEOF_STRUCT_PBUF + usize::from(offset)),
                    );
                    pbuf_init_alloced_pbuf(q, payload.cast(), rem_len, qlen, type_, 0);
                }
                // SAFETY: just initialized.
                let payload = unsafe { (*q).payload };
                lwip_assert!(
                    "pbuf_alloc: pbuf q->payload properly aligned",
                    payload.addr().is_multiple_of(config::MEM_ALIGNMENT)
                );
                lwip_assert!(
                    "PBUF_POOL_BUFSIZE must be bigger than MEM_ALIGNMENT",
                    room as u32 > 0
                );
                if p.is_null() {
                    // Allocated head of pbuf chain (into p).
                    p = q;
                } else {
                    // Make previous pbuf point to this pbuf.
                    // SAFETY: `last` is the chain's last pbuf.
                    unsafe { (*last).next = ptr::NonNull::new(q) };
                }
                last = q;
                rem_len -= qlen;
                offset = 0;
                if rem_len == 0 {
                    break;
                }
            }
            p
        }
        PBUF_RAM => {
            let payload_len: MemSize =
                mem_align_size(offset.into()).wrapping_add(mem_align_size(length.into()));
            let alloc_len: MemSize = mem_align_size(SIZEOF_STRUCT_PBUF).wrapping_add(payload_len);

            // Bug #50040: Check for integer overflow when calculating alloc_len.
            if payload_len < mem_align_size(length.into())
                || alloc_len < mem_align_size(length.into())
            {
                return ptr::null_mut();
            }

            // If pbuf is to be allocated in RAM, allocate memory for it.
            // SAFETY: `mem_malloc` takes any size.
            let p = unsafe { mem_malloc(alloc_len) }.cast::<Pbuf>();
            if p.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: `alloc_len` bytes hold a struct pbuf and its payload after it.
            unsafe {
                let payload = mem_align(
                    p.cast::<u8>()
                        .wrapping_add(SIZEOF_STRUCT_PBUF + usize::from(offset)),
                );
                pbuf_init_alloced_pbuf(p, payload.cast(), length, length, type_, 0);
            }
            // SAFETY: just initialized.
            let payload = unsafe { (*p).payload };
            lwip_assert!(
                "pbuf_alloc: pbuf->payload properly aligned",
                payload.addr().is_multiple_of(config::MEM_ALIGNMENT)
            );
            p
        }
        _ => {
            lwip_assert!("pbuf_alloc: erroneous type", false);
            ptr::null_mut()
        }
    }
}

/// Allocates a pbuf for referenced data. Referenced data can be volatile (`PBUF_REF`) or
/// long-lived (`PBUF_ROM`).
///
/// The actual memory allocated for the pbuf is determined by the layer at which the pbuf
/// is allocated and the requested size (from the size parameter).
///
/// # Safety
///
/// `payload` is null or valid for `length` bytes for as long as the pbuf refers to it:
/// the stack reads it, and for `PBUF_REF` may write it, through the pbuf.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_alloc_reference(
    payload: *mut c_void,
    length: u16,
    type_: PbufType,
) -> *mut Pbuf {
    lwip_assert!("invalid pbuf_type", type_ == PBUF_REF || type_ == PBUF_ROM);
    // Only allocate memory for the pbuf structure.
    // SAFETY: a pool element, or null.
    let p = unsafe { memp_malloc(config::MEMP_PBUF) }.cast::<Pbuf>();
    if p.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a MEMP_PBUF element holds a struct pbuf.
    unsafe { pbuf_init_alloced_pbuf(p, payload, length, length, type_, 0) };
    p
}

/// Initialize a custom pbuf (already allocated). Example of custom pbuf usage:
/// zerocopyrxtx.
///
/// `payload_mem` is a pointer to the buffer that is used for payload and headers, or
/// null; `payload_mem_len` is its size, which must be at least the layer's header room
/// plus `length`.
///
/// Returns a pointer to the initialized pbuf (for convenience), or null if the buffer is
/// too small.
///
/// # Safety
///
/// `p` is writable for a `struct pbuf_custom`, and `payload_mem` is null or valid for
/// `payload_mem_len` bytes.
#[cfg(lwip_support_custom_pbuf)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_alloced_custom(
    l: PbufLayer,
    length: u16,
    type_: PbufType,
    p: *mut PbufCustom,
    payload_mem: *mut c_void,
    payload_mem_len: u16,
) -> *mut Pbuf {
    let offset = l as u16;
    if mem_align_size(offset.into()).wrapping_add(length.into()) > usize::from(payload_mem_len) {
        return ptr::null_mut();
    }

    let payload = if payload_mem.is_null() {
        ptr::null_mut()
    } else {
        payload_mem
            .cast::<u8>()
            .wrapping_add(mem_align_size(offset.into()))
            .cast()
    };
    // SAFETY: `p` is writable, per the caller; `pbuf` is its first field.
    unsafe {
        let pbuf = ptr::addr_of_mut!((*p).pbuf);
        pbuf_init_alloced_pbuf(pbuf, payload, length, length, type_, PBUF_FLAG_IS_CUSTOM);
        pbuf
    }
}

/// Shrink a pbuf chain to a desired length.
///
/// Depending on the desired length, the first few pbufs in a chain might be skipped and
/// left unchanged. The new last pbuf in the chain will be resized, and any remaining pbufs
/// will be freed.
///
/// If the pbuf is ROM/REF, only the `->tot_len` and `->len` fields are adjusted. May not be
/// called on a packet queue. Despite its name, pbuf_realloc cannot grow the size of a
/// pbuf (chain).
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_realloc(p: *mut Pbuf, new_len: u16) {
    lwip_assert!("pbuf_realloc: p != NULL", !p.is_null());

    // SAFETY: `p` is a well-formed chain, per the caller; each `q` below is on it.
    unsafe {
        if new_len >= (*p).tot_len {
            // Enlarging not yet supported.
            return;
        }

        // The pbuf chain grows by (new_len - p->tot_len) bytes (which may be negative in
        // case of shrinking).
        let shrink = (*p).tot_len - new_len;

        // First, step over any pbufs that should remain in the chain.
        let mut rem_len = new_len;
        let mut q = p;
        // Should this pbuf be kept?
        while rem_len > (*q).len {
            // Decrease remaining length by pbuf length.
            rem_len -= (*q).len;
            // Decrease total length indicator.
            (*q).tot_len = (*q).tot_len.wrapping_sub(shrink);
            // Proceed to next pbuf in chain.
            q = (*q).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
            lwip_assert!("pbuf_realloc: q != NULL", !q.is_null());
        }
        // We have now reached the new last pbuf (in q), rem_len == desired length for
        // pbuf q.

        // Shrink allocated memory for PBUF_RAM (other types merely adjust their length
        // fields).
        if (*q).type_internal & PBUF_TYPE_ALLOC_SRC_MASK == PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP
            && rem_len != (*q).len
            && (!cfg!(lwip_support_custom_pbuf) || (*q).flags & PBUF_FLAG_IS_CUSTOM == 0)
        {
            // Reallocate and adjust the length of the pbuf that will be split.
            let size = ((*q).payload.addr() - q.addr()).wrapping_add(rem_len.into());
            let r = mem_trim(q.cast(), size).cast::<Pbuf>();
            lwip_assert!("mem_trim returned r == NULL", !r.is_null());
            // Taken care of in mem_trim.
            lwip_assert!("mem_trim returned r != q", r == q);
        }
        // Adjust length fields for new last pbuf.
        (*q).len = rem_len;
        (*q).tot_len = (*q).len;

        // Any remaining pbufs in chain?
        if let Some(next) = (*q).next {
            // Free remaining pbufs in chain.
            pbuf_free(next.as_ptr());
        }
        // q is last packet in chain.
        (*q).next = None;
    }
}

/// Adjusts the payload pointer to reveal headers in the payload.
///
/// Returns 0 on success, 1 on failure (not enough room, or `p` null).
///
/// # Safety
///
/// See the module's safety section.
unsafe fn pbuf_add_header_impl(p: *mut Pbuf, header_size_increment: usize, force: bool) -> u8 {
    lwip_assert!("p != NULL", !p.is_null());
    if p.is_null() || header_size_increment > 0xFFFF {
        return 1;
    }
    if header_size_increment == 0 {
        return 0;
    }

    let increment_magnitude = header_size_increment as u16;
    // SAFETY: `p` is a live pbuf, per the caller.
    unsafe {
        // Do not allow tot_len to wrap as a result.
        if increment_magnitude.wrapping_add((*p).tot_len) < increment_magnitude {
            return 1;
        }

        let payload;
        // Pbuf types containing payloads?
        if (*p).type_internal & PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS != 0 {
            // Set new payload pointer.
            payload = (*p)
                .payload
                .cast::<u8>()
                .wrapping_sub(header_size_increment);
            // Boundary check fails?
            if payload.addr() < p.addr() + SIZEOF_STRUCT_PBUF {
                // Bail out unsuccessfully.
                return 1;
            }
        // pbuf types referring to external payloads?
        } else if force {
            // Hide a header in the payload?
            payload = (*p)
                .payload
                .cast::<u8>()
                .wrapping_sub(header_size_increment);
        } else {
            // Cannot expand payload to front (yet!). Bail out unsuccessfully.
            return 1;
        }

        // Modify pbuf fields.
        (*p).payload = payload.cast();
        (*p).len = (*p).len.wrapping_add(increment_magnitude);
        (*p).tot_len = (*p).tot_len.wrapping_add(increment_magnitude);
    }
    0
}

/// Adjusts the payload pointer to reveal headers in the payload.
///
/// Adjusts the `->payload` pointer so that space for a header appears in the pbuf
/// payload. The `->payload`, `->tot_len` and `->len` fields are adjusted.
///
/// PBUF_ROM and PBUF_REF type buffers cannot have their sizes increased, so the call will
/// fail. A check is made that the increase in header size does not move the payload
/// pointer in front of the start of the buffer.
///
/// Returns non-zero on failure, zero on success.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_add_header(p: *mut Pbuf, header_size_increment: usize) -> u8 {
    // SAFETY: forwarded from the caller.
    unsafe { pbuf_add_header_impl(p, header_size_increment, false) }
}

/// Same as `pbuf_add_header` but does not check if `header_size > 0` is allowed. This is
/// used internally only, to allow PBUF_REF for RX.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_add_header_force(p: *mut Pbuf, header_size_increment: usize) -> u8 {
    // SAFETY: forwarded from the caller.
    unsafe { pbuf_add_header_impl(p, header_size_increment, true) }
}

/// Adjusts the payload pointer to hide headers in the payload.
///
/// Adjusts the `->payload` pointer so that space for a header disappears in the pbuf
/// payload. The `->payload`, `->tot_len` and `->len` fields are adjusted.
///
/// Returns non-zero on failure, zero on success.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_remove_header(p: *mut Pbuf, header_size_decrement: usize) -> u8 {
    lwip_assert!("p != NULL", !p.is_null());
    if p.is_null() || header_size_decrement > 0xFFFF {
        return 1;
    }
    if header_size_decrement == 0 {
        return 0;
    }

    let increment_magnitude = header_size_decrement as u16;
    // SAFETY: `p` is a live pbuf, per the caller.
    unsafe {
        // Check that we aren't going to move off the end of the pbuf.
        // LWIP_ERROR("increment_magnitude <= p->len", ..., return 1;)
        if increment_magnitude > (*p).len {
            return 1;
        }

        // Increase payload pointer (guarded by length check above).
        (*p).payload = (*p)
            .payload
            .cast::<u8>()
            .wrapping_add(header_size_decrement)
            .cast();
        // Modify pbuf length fields.
        (*p).len -= increment_magnitude;
        (*p).tot_len = (*p).tot_len.wrapping_sub(increment_magnitude);
    }
    0
}

/// `pbuf_header` and `pbuf_header_force`: a positive increment adds a header, a negative
/// one removes it.
///
/// # Safety
///
/// See the module's safety section.
unsafe fn pbuf_header_impl(p: *mut Pbuf, header_size_increment: i16, force: bool) -> u8 {
    if header_size_increment < 0 {
        // SAFETY: forwarded from the caller.
        unsafe { pbuf_remove_header(p, (-i32::from(header_size_increment)) as usize) }
    } else {
        // SAFETY: forwarded from the caller.
        unsafe { pbuf_add_header_impl(p, header_size_increment as usize, force) }
    }
}

/// Adjusts the payload pointer to hide or reveal headers in the payload: a positive
/// `header_size_increment` reveals a header of that size, a negative one hides one.
///
/// Returns non-zero on failure, zero on success.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_header(p: *mut Pbuf, header_size_increment: i16) -> u8 {
    // SAFETY: forwarded from the caller.
    unsafe { pbuf_header_impl(p, header_size_increment, false) }
}

/// Same as `pbuf_header` but does not check if `header_size > 0` is allowed. This is used
/// internally only, to allow PBUF_REF for RX.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_header_force(p: *mut Pbuf, header_size_increment: i16) -> u8 {
    // SAFETY: forwarded from the caller.
    unsafe { pbuf_header_impl(p, header_size_increment, true) }
}

/// Similar to `pbuf_header(-size)` but de-refs header pbufs for `size >= p->len`.
///
/// Returns the new head pbuf.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_free_header(q: *mut Pbuf, size: u16) -> *mut Pbuf {
    let mut p = q;
    let mut free_left = size;
    // SAFETY: each `p` is on the chain, per the caller.
    unsafe {
        while free_left != 0 && !p.is_null() {
            if free_left >= (*p).len {
                let f = p;
                free_left -= (*p).len;
                p = (*p).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
                (*f).next = None;
                pbuf_free(f);
            } else {
                pbuf_remove_header(p, free_left.into());
                free_left = 0;
            }
        }
    }
    p
}

/// Dereference a pbuf chain or queue and deallocate any no-longer-used pbufs at the head
/// of this chain or queue.
///
/// Decrements the pbuf reference count. If it reaches zero, the pbuf is deallocated. For
/// a pbuf chain, this is repeated for each pbuf in the chain, up to the first pbuf which
/// has a non-zero reference count after decrementing. So, when all reference counts are
/// one, the whole chain is free'd.
///
/// Returns the number of pbufs that were de-allocated from the head of the chain.
///
/// # Safety
///
/// See the module's safety section; each pbuf's allocation source and custom free
/// function are as it was allocated with.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_free(p: *mut Pbuf) -> u8 {
    if p.is_null() {
        lwip_assert!("p != NULL", !p.is_null());
        return 0;
    }

    let mut p = p;
    let mut count: u8 = 0;
    // De-allocate all consecutive pbufs from the head of the chain that obtain a zero
    // reference count after decrementing.
    // SAFETY: each `p` is on the chain, per the caller, until it is freed.
    unsafe {
        while !p.is_null() {
            // Since decrementing ref cannot be guaranteed to be a single machine operation
            // we must protect it. We put the new ref into a local variable to prevent
            // further protection.
            let ref_ = locked(|| {
                // All pbufs in a chain are referenced at least once.
                lwip_assert!("pbuf_free: p->ref > 0", (*p).ref_ > 0);
                // Decrease reference count (number of pointers to pbuf).
                (*p).ref_ = (*p).ref_.wrapping_sub(1);
                (*p).ref_
            });
            // This pbuf is no longer referenced to?
            if ref_ == 0 {
                // Remember next pbuf in chain for next iteration.
                let q = (*p).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
                let alloc_src = (*p).type_internal & PBUF_TYPE_ALLOC_SRC_MASK;
                // Is this a custom pbuf?
                if cfg!(lwip_support_custom_pbuf) && (*p).flags & PBUF_FLAG_IS_CUSTOM != 0 {
                    let pc = p.cast::<PbufCustom>();
                    let free_function = (*pc).custom_free_function;
                    lwip_assert!("pc->custom_free_function != NULL", free_function.is_some());
                    if let Some(free_function) = free_function {
                        free_function(p);
                    }
                } else if alloc_src == PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL {
                    // Is this a pbuf from the pool?
                    memp_free(config::MEMP_PBUF_POOL, p.cast());
                } else if alloc_src == PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF {
                    // Is this a ROM or RAM referencing pbuf?
                    memp_free(config::MEMP_PBUF, p.cast());
                } else if alloc_src == PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP {
                    // type == PBUF_RAM
                    mem_free(p.cast());
                } else {
                    // @todo: support freeing other types
                    lwip_assert!("invalid pbuf type", false);
                }
                count = count.wrapping_add(1);
                // Proceed to next pbuf.
                p = q;
            } else {
                // p->ref > 0, this pbuf is still referenced to (and so the remaining pbufs
                // in chain as well). Stop walking through the chain.
                p = ptr::null_mut();
            }
        }
    }
    // Return number of de-allocated pbufs.
    count
}

/// Count number of pbufs in a chain.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_clen(p: *const Pbuf) -> u16 {
    // SAFETY: forwarded from the caller.
    unsafe { crate::types::pbuf_iter(p) }.fold(0_u16, |len, _| len.wrapping_add(1))
}

/// Increment the reference count of the pbuf.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_ref(p: *mut Pbuf) {
    // Pbuf given?
    if !p.is_null() {
        // SAFETY: a live pbuf, per the caller.
        unsafe {
            locked(|| (*p).ref_ = (*p).ref_.wrapping_add(1));
            lwip_assert!("pbuf ref overflow", (*p).ref_ > 0);
        }
    }
}

/// Concatenate two pbufs (each may be a pbuf chain) and take over the caller's reference
/// of the tail pbuf.
///
/// The caller must not reference the tail pbuf afterwards. Use `pbuf_chain()` for that
/// purpose.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_cat(h: *mut Pbuf, t: *mut Pbuf) {
    // LWIP_ERROR("(h != NULL) && (t != NULL) (programmer violates API)", ..., return;)
    if h.is_null() || t.is_null() {
        return;
    }

    // SAFETY: two well-formed chains, per the caller.
    unsafe {
        // Proceed to last pbuf of chain.
        let mut p = h;
        while let Some(next) = (*p).next {
            // Add total length of second chain to all totals of first chain.
            (*p).tot_len = (*p).tot_len.wrapping_add((*t).tot_len);
            p = next.as_ptr();
        }
        // { p is last pbuf of first h chain, p->next == NULL }
        lwip_assert!(
            "p->tot_len == p->len (of last pbuf in chain)",
            (*p).tot_len == (*p).len
        );
        lwip_assert!("p->next == NULL", (*p).next.is_none());
        // Add total length of second chain to last pbuf total of first chain.
        (*p).tot_len = (*p).tot_len.wrapping_add((*t).tot_len);
        // Chain last pbuf of head (p) with first of tail (t).
        (*p).next = ptr::NonNull::new(t);
        // p->next now references t, but the caller will drop its reference to t, so
        // netto there is no change to the reference count of t.
    }
}

/// Chain two pbufs (or pbuf chains) together.
///
/// The caller MUST call `pbuf_free(t)` once it has stopped using it. Use `pbuf_cat()`
/// instead if you no longer use t.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_chain(h: *mut Pbuf, t: *mut Pbuf) {
    // SAFETY: forwarded from the caller.
    unsafe {
        pbuf_cat(h, t);
        // t is now referenced by h.
        pbuf_ref(t);
    }
}

/// Dechains the first pbuf from its succeeding pbufs in the chain.
///
/// Makes `p->tot_len` field equal to `p->len`.
///
/// Returns the remainder of the pbuf chain, or null if it was de-allocated. May not be
/// called on a packet queue.
///
/// # Safety
///
/// See the module's safety section; `p` is not null.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_dechain(p: *mut Pbuf) -> *mut Pbuf {
    let mut tail_gone: u8 = 1;
    // SAFETY: a well-formed chain, per the caller.
    unsafe {
        // Tail.
        let q = (*p).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
        // pbuf has successor in chain?
        if !q.is_null() {
            // Assert tot_len invariant: (p->tot_len == p->len + (p->next? p->next->tot_len: 0).
            lwip_assert!(
                "p->tot_len == p->len + q->tot_len",
                i32::from((*q).tot_len) == i32::from((*p).tot_len) - i32::from((*p).len)
            );
            // Enforce invariant if assertion is disabled.
            (*q).tot_len = (*p).tot_len.wrapping_sub((*p).len);
            // Decouple pbuf from remainder.
            (*p).next = None;
            // Total length of pbuf p is its own length only.
            (*p).tot_len = (*p).len;
            // q is no longer referenced by p, free it.
            tail_gone = pbuf_free(q);
            // Return remaining tail or NULL if deallocated.
        }
        // Assert tot_len invariant: (p->tot_len == p->len + (p->next? p->next->tot_len: 0).
        lwip_assert!("p->tot_len == p->len", (*p).tot_len == (*p).len);
        if tail_gone > 0 { ptr::null_mut() } else { q }
    }
}

/// Copy the contents of one packet buffer into another.
///
/// Only one packet is copied, no packet queue! `p_to` must have at least as much space as
/// `p_from`'s `tot_len`.
///
/// Returns `ERR_OK` if pbuf was copied, `ERR_ARG` if one of the pbufs is NULL or `p_to` is
/// not big enough to hold `p_from`, `ERR_VAL` if any of the pbufs are part of a queue.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_copy(p_to: *mut Pbuf, p_from: *const Pbuf) -> ErrT {
    // LWIP_ERROR("pbuf_copy: invalid source", p_from != NULL, return ERR_ARG;)
    if p_from.is_null() {
        return ERR_ARG;
    }
    // SAFETY: forwarded from the caller.
    unsafe { pbuf_copy_partial_pbuf(p_to, p_from, (*p_from).tot_len, 0) }
}

/// Copy part or all of the contents of one packet buffer into another: `copy_len` bytes of
/// `p_from` into `p_to`, starting `offset` bytes into `p_to`.
///
/// Returns `ERR_OK` if `copy_len` bytes were copied, `ERR_ARG` if one of the pbufs is NULL
/// or the pbufs are not big enough, `ERR_VAL` if any of the pbufs are part of a queue.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_copy_partial_pbuf(
    p_to: *mut Pbuf,
    p_from: *const Pbuf,
    copy_len: u16,
    offset: u16,
) -> ErrT {
    let mut p_to = p_to;
    let mut p_from = p_from;
    let mut copy_len = copy_len;
    let mut offset_to = usize::from(offset);
    let mut offset_from: usize = 0;

    // SAFETY: two well-formed chains, per the caller; each copy stays inside the current
    // pbuf of each, which the length checks guarantee.
    unsafe {
        // Is the source pbuf big enough?
        if p_from.is_null() || (*p_from).tot_len < copy_len {
            return ERR_ARG;
        }
        // Is the target pbuf big enough?
        if p_to.is_null() || i32::from((*p_to).tot_len) < i32::from(offset) + i32::from(copy_len) {
            return ERR_ARG;
        }

        loop {
            // Copy one part of the original chain.
            let to_room = usize::from((*p_to).len).wrapping_sub(offset_to);
            let from_left = usize::from((*p_from).len).wrapping_sub(offset_from);
            // Copy the smaller of the two remaining parts, and no more than asked.
            let len = if to_room >= from_left {
                from_left
            } else {
                to_room
            };
            let len = len.min(copy_len.into());
            // The pbufs may share a payload: copy as memmove does, not memcpy.
            ptr::copy(
                (*p_from).payload.cast::<u8>().add(offset_from),
                (*p_to).payload.cast::<u8>().add(offset_to),
                len,
            );
            offset_to += len;
            offset_from += len;
            copy_len -= len as u16;
            lwip_assert!(
                "offset_to <= p_to->len",
                offset_to <= usize::from((*p_to).len)
            );
            lwip_assert!(
                "offset_from <= p_from->len",
                offset_from <= usize::from((*p_from).len)
            );
            if offset_from >= usize::from((*p_from).len) {
                // On to next p_from (if any).
                offset_from = 0;
                p_from = (*p_from)
                    .next
                    .map_or(ptr::null(), |next| next.as_ptr().cast_const());
                // LWIP_ERROR("p_from != NULL", (p_from != NULL) || (copy_len == 0), return ERR_ARG;)
                if p_from.is_null() && copy_len != 0 {
                    return ERR_ARG;
                }
            }
            if offset_to == usize::from((*p_to).len) {
                // On to next p_to (if any).
                offset_to = 0;
                p_to = (*p_to).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
                // LWIP_ERROR("p_to != NULL", (p_to != NULL) || (copy_len == 0), return ERR_ARG;)
                if p_to.is_null() && copy_len != 0 {
                    return ERR_ARG;
                }
            }

            if !p_from.is_null() && (*p_from).len == (*p_from).tot_len {
                // Don't copy more than one packet!
                // LWIP_ERROR("pbuf_copy() does not allow packet queues!", ..., return ERR_VAL;)
                if (*p_from).next.is_some() {
                    return ERR_VAL;
                }
            }
            if !p_to.is_null() && (*p_to).len == (*p_to).tot_len {
                // Don't copy more than one packet!
                if (*p_to).next.is_some() {
                    return ERR_VAL;
                }
            }
            if copy_len == 0 {
                break;
            }
        }
    }
    ERR_OK
}

/// Copy (part of) the contents of a packet buffer to an application supplied buffer.
///
/// Returns the number of bytes copied, or 0 on failure.
///
/// # Safety
///
/// See the module's safety section; `dataptr` is null or writable for `len` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_copy_partial(
    buf: *const Pbuf,
    dataptr: *mut c_void,
    len: u16,
    offset: u16,
) -> u16 {
    let mut left: u16 = 0;
    let mut copied_total: u16 = 0;
    let mut len = len;
    let mut offset = offset;

    // LWIP_ERROR("pbuf_copy_partial: invalid buf", (buf != NULL), return 0;)
    // LWIP_ERROR("pbuf_copy_partial: invalid dataptr", (dataptr != NULL), return 0;)
    if buf.is_null() || dataptr.is_null() {
        return 0;
    }

    // Note some systems use byte copy if dataptr or one of the pbuf payload pointers are
    // unaligned.
    // SAFETY: a well-formed chain and a buffer of `len` bytes, per the caller; each copy
    // stays inside both.
    unsafe {
        let mut p = buf;
        while len != 0 && !p.is_null() {
            if offset != 0 && offset >= (*p).len {
                // Don't copy from this buffer -> on to the next.
                offset -= (*p).len;
            } else {
                // Copy from this buffer. Maybe only partially.
                let buf_copy_len = ((*p).len - offset).min(len);
                // Copy the necessary parts of the buffer.
                ptr::copy(
                    (*p).payload.cast::<u8>().add(offset.into()),
                    dataptr.cast::<u8>().add(left.into()),
                    buf_copy_len.into(),
                );
                copied_total = copied_total.wrapping_add(buf_copy_len);
                left = left.wrapping_add(buf_copy_len);
                len -= buf_copy_len;
                offset = 0;
            }
            p = (*p)
                .next
                .map_or(ptr::null(), |next| next.as_ptr().cast_const());
        }
    }
    copied_total
}

/// Get part of a pbuf's payload as contiguous memory. The returned memory is either a
/// pointer into the pbuf's payload or, if split over multiple pbufs, a copy into the
/// user-supplied buffer.
///
/// Returns the pointer to `len` contiguous bytes, or null on failure.
///
/// # Safety
///
/// See the module's safety section; `buffer` is null or writable for `bufsize` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_get_contiguous(
    p: *const Pbuf,
    buffer: *mut c_void,
    bufsize: usize,
    len: u16,
    offset: u16,
) -> *mut c_void {
    // LWIP_ERROR("pbuf_get_contiguous: invalid buf", (p != NULL), return NULL;)
    // LWIP_ERROR("pbuf_get_contiguous: invalid dataptr", (buffer != NULL), return NULL;)
    // LWIP_ERROR("pbuf_get_contiguous: invalid dataptr", (bufsize >= len), return NULL;)
    if p.is_null() || buffer.is_null() || bufsize < usize::from(len) {
        return ptr::null_mut();
    }

    let mut out_offset: u16 = 0;
    // SAFETY: a well-formed chain, per the caller.
    unsafe {
        let q = pbuf_skip_const(p, offset, Some(&mut out_offset));
        if q.is_null() {
            return ptr::null_mut();
        }
        if i32::from((*q).len) >= i32::from(out_offset) + i32::from(len) {
            // All data in this pbuf, return zero-copy.
            return (*q).payload.cast::<u8>().add(out_offset.into()).cast();
        }
        // Need to copy.
        if pbuf_copy_partial(q, buffer, len, out_offset) != len {
            // Copying failed: pbuf is too short.
            return ptr::null_mut();
        }
    }
    buffer
}

/// Split a pbuf chain into two parts, the first no longer than 64k: the pbufs after it
/// are returned in `rest`, which is null if the whole chain fits.
///
/// # Safety
///
/// See the module's safety section; `rest` is writable.
#[cfg(any(pbuf_split_64k, test))]
#[cfg_attr(all(target_os = "none", pbuf_split_64k), unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_split_64k(p: *mut Pbuf, rest: *mut *mut Pbuf) {
    // SAFETY: a well-formed chain and a writable `rest`, per the caller.
    unsafe {
        *rest = ptr::null_mut();
        if p.is_null() {
            return;
        }
        let Some(first_next) = (*p).next else {
            return;
        };
        let mut tot_len_front = (*p).len;
        let mut i = p;
        let mut r = first_next.as_ptr();

        // Continue until the total length (summed up as u16_t) overflows.
        while !r.is_null() && tot_len_front.wrapping_add((*r).len) >= tot_len_front {
            tot_len_front = tot_len_front.wrapping_add((*r).len);
            i = r;
            r = (*r).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
        }
        // i now points to last packet of the first segment. Set next pointer to NULL.
        (*i).next = None;

        if !r.is_null() {
            // Update the tot_len field in the first part.
            let mut i = p;
            while !i.is_null() {
                (*i).tot_len = (*i).tot_len.wrapping_sub((*r).tot_len);
                lwip_assert!(
                    "tot_len/len mismatch in last pbuf",
                    (*i).next.is_some() || (*i).tot_len == (*i).len
                );
                i = (*i).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
            }
            if (*p).flags & PBUF_FLAG_TCP_FIN != 0 {
                (*r).flags |= PBUF_FLAG_TCP_FIN;
            }

            // tot_len field in rest does not need modifications; reference counters do not
            // need modifications.
            *rest = r;
        }
    }
}

/// Actual implementation of `pbuf_skip()` but returning const pointer...
///
/// # Safety
///
/// See the module's safety section.
unsafe fn pbuf_skip_const(
    in_: *const Pbuf,
    in_offset: u16,
    out_offset: Option<&mut u16>,
) -> *const Pbuf {
    let mut offset_left = in_offset;
    let mut q = in_;

    // Get the correct pbuf.
    // SAFETY: each `q` is on the chain, per the caller.
    unsafe {
        while !q.is_null() && (*q).len <= offset_left {
            offset_left -= (*q).len;
            q = (*q)
                .next
                .map_or(ptr::null(), |next| next.as_ptr().cast_const());
        }
    }
    if let Some(out_offset) = out_offset {
        *out_offset = offset_left;
    }
    q
}

/// Skip a number of bytes at the start of a pbuf.
///
/// Returns the pbuf in the queue where the offset is, or null; its offset into that pbuf
/// is stored in `out_offset` if it is not null.
///
/// # Safety
///
/// See the module's safety section; `out_offset` is null or writable.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_skip(
    in_: *mut Pbuf,
    in_offset: u16,
    out_offset: *mut u16,
) -> *mut Pbuf {
    // SAFETY: forwarded from the caller.
    unsafe { pbuf_skip_const(in_, in_offset, out_offset.as_mut()) }.cast_mut()
}

/// Copy application supplied data into a pbuf. This function can only be used to copy the
/// equivalent of `buf->tot_len` data.
///
/// Returns `ERR_OK` if successful, `ERR_MEM` if the pbuf is not big enough.
///
/// # Safety
///
/// See the module's safety section; `dataptr` is null or readable for `len` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_take(buf: *mut Pbuf, dataptr: *const c_void, len: u16) -> ErrT {
    let mut total_copy_len = usize::from(len);
    let mut copied_total: usize = 0;

    // LWIP_ERROR("pbuf_take: invalid buf", (buf != NULL), return ERR_ARG;)
    // LWIP_ERROR("pbuf_take: invalid dataptr", (dataptr != NULL), return ERR_ARG;)
    // LWIP_ERROR("pbuf_take: buf not large enough", (buf->tot_len >= len), return ERR_MEM;)
    if buf.is_null() || dataptr.is_null() {
        return ERR_ARG;
    }
    // SAFETY: a well-formed chain and a buffer of `len` bytes, per the caller; each copy
    // stays inside both.
    unsafe {
        if (*buf).tot_len < len {
            return ERR_MEM;
        }

        // Note some systems use byte copy if dataptr or one of the pbuf payload pointers
        // are unaligned.
        let mut p = buf;
        while total_copy_len != 0 {
            lwip_assert!("pbuf_take: invalid pbuf", !p.is_null());
            let buf_copy_len = total_copy_len.min((*p).len.into());
            // Copy the necessary parts of the buffer.
            ptr::copy(
                dataptr.cast::<u8>().add(copied_total),
                (*p).payload.cast::<u8>(),
                buf_copy_len,
            );
            total_copy_len -= buf_copy_len;
            copied_total += buf_copy_len;
            p = (*p).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
        }
    }
    lwip_assert!(
        "did not copy all data",
        total_copy_len == 0 && copied_total == usize::from(len)
    );
    ERR_OK
}

/// Same as `pbuf_take()` but puts data at an offset.
///
/// Returns `ERR_OK` if successful, `ERR_MEM` if the pbuf is not big enough.
///
/// # Safety
///
/// See the module's safety section; `dataptr` is readable for `len` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_take_at(
    buf: *mut Pbuf,
    dataptr: *const c_void,
    len: u16,
    offset: u16,
) -> ErrT {
    let mut target_offset: u16 = 0;
    // SAFETY: a well-formed chain and a buffer of `len` bytes, per the caller.
    unsafe {
        let q = pbuf_skip(buf, offset, &mut target_offset);

        // Return requested data if pbuf is OK.
        if !q.is_null() && i32::from((*q).tot_len) >= i32::from(target_offset) + i32::from(len) {
            lwip_assert!("check pbuf_skip result", target_offset < (*q).len);
            let first_copy_len = ((*q).len - target_offset).min(len);
            ptr::copy(
                dataptr.cast::<u8>(),
                (*q).payload.cast::<u8>().add(target_offset.into()),
                first_copy_len.into(),
            );
            let remaining_len = len - first_copy_len;
            let src_ptr = dataptr.cast::<u8>().add(first_copy_len.into());
            if remaining_len > 0 {
                let next = (*q).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
                return pbuf_take(next, src_ptr.cast(), remaining_len);
            }
            return ERR_OK;
        }
    }
    ERR_MEM
}

/// Creates a single pbuf out of a queue of pbufs.
///
/// Either the source pbuf `p` is freed by this function or the original pbuf `p` is
/// returned, therefore the caller has to check the result!
///
/// # Safety
///
/// See the module's safety section; `p` is not null.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_coalesce(p: *mut Pbuf, layer: PbufLayer) -> *mut Pbuf {
    // SAFETY: a well-formed chain, per the caller.
    unsafe {
        if (*p).next.is_none() {
            return p;
        }
        let q = pbuf_clone(layer, PBUF_RAM, p);
        if q.is_null() {
            // @todo: what do we do now?
            return p;
        }
        pbuf_free(p);
        q
    }
}

/// Allocates a new pbuf of same length (via `pbuf_alloc()`) and copies the source pbuf
/// into this new pbuf (using `pbuf_copy()`).
///
/// Returns a new pbuf or null if allocation fails.
///
/// # Safety
///
/// See the module's safety section; `p` is not null.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_clone(layer: PbufLayer, type_: PbufType, p: *mut Pbuf) -> *mut Pbuf {
    // SAFETY: a well-formed chain, per the caller.
    unsafe {
        let q = pbuf_alloc(layer, (*p).tot_len, type_);
        if q.is_null() {
            return ptr::null_mut();
        }
        let err = pbuf_copy(q, p);
        // In case of LWIP_NOASSERT.
        let _ = err;
        lwip_assert!("pbuf_copy failed", err == ERR_OK);
        q
    }
}

/// Get one byte from the specified position in a pbuf.
///
/// Returns 0 if `offset >= p->tot_len`.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_get_at(p: *const Pbuf, offset: u16) -> u8 {
    // SAFETY: forwarded from the caller.
    let ret = unsafe { pbuf_try_get_at(p, offset) };
    if ret >= 0 { ret as u8 } else { 0 }
}

/// Get one byte from the specified position in a pbuf.
///
/// Returns the byte, or -1 if `offset >= p->tot_len`.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_try_get_at(p: *const Pbuf, offset: u16) -> c_int {
    let mut q_idx: u16 = 0;
    // SAFETY: a well-formed chain, per the caller; the index is inside `q`'s payload.
    unsafe {
        let q = pbuf_skip_const(p, offset, Some(&mut q_idx));
        // Return requested data if pbuf is OK.
        if !q.is_null() && (*q).len > q_idx {
            return c_int::from((*q).payload.cast::<u8>().add(q_idx.into()).read());
        }
    }
    -1
}

/// Put one byte to the specified position in a pbuf. WARNING: `data` is not written if
/// `offset >= p->tot_len`.
///
/// # Safety
///
/// See the module's safety section.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_put_at(p: *mut Pbuf, offset: u16, data: u8) {
    let mut q_idx: u16 = 0;
    // SAFETY: a well-formed chain, per the caller; the index is inside `q`'s payload.
    unsafe {
        let q = pbuf_skip(p, offset, &mut q_idx);
        // Write requested data if pbuf is OK.
        if !q.is_null() && (*q).len > q_idx {
            (*q).payload.cast::<u8>().add(q_idx.into()).write(data);
        }
    }
}

/// Compare pbuf contents at specified offset with memory `s2`, both of length `n`.
///
/// Returns zero if equal, nonzero otherwise (0xffff if `p` is too short, diffoffset+1
/// otherwise).
///
/// # Safety
///
/// See the module's safety section; `p` is not null and `s2` is readable for `n` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_memcmp(
    p: *const Pbuf,
    offset: u16,
    s2: *const c_void,
    n: u16,
) -> u16 {
    let mut start = offset;
    let mut q = p;

    // SAFETY: a well-formed chain and a buffer of `n` bytes, per the caller.
    unsafe {
        if i32::from((*p).tot_len) < i32::from(offset) + i32::from(n) {
            return 0xffff;
        }

        // Get the correct pbuf from chain. We know it succeeds because of p->tot_len
        // check above.
        while !q.is_null() && (*q).len <= start {
            start -= (*q).len;
            q = (*q)
                .next
                .map_or(ptr::null(), |next| next.as_ptr().cast_const());
        }

        // Return requested data if pbuf is OK.
        for i in 0..n {
            // We know pbuf_get_at() succeeds because of p->tot_len check above.
            let a = pbuf_get_at(q, start.wrapping_add(i));
            let b = s2.cast::<u8>().add(i.into()).read();
            if a != b {
                return (u32::from(i) + 1).min(0xFFFF) as u16;
            }
        }
    }
    0
}

/// Find occurrence of `mem` (with length `mem_len`) in pbuf `p`, starting at offset
/// `start_offset`.
///
/// Returns 0xFFFF if substr was not found in p or the index where it was found.
///
/// # Safety
///
/// See the module's safety section; `p` is not null and `mem` is readable for `mem_len`
/// bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_memfind(
    p: *const Pbuf,
    mem: *const c_void,
    mem_len: u16,
    start_offset: u16,
) -> u16 {
    // SAFETY: forwarded from the caller.
    unsafe {
        let max_cmp_start = (*p).tot_len.wrapping_sub(mem_len);
        if i32::from((*p).tot_len) >= i32::from(mem_len) + i32::from(start_offset) {
            for i in start_offset..=max_cmp_start {
                let plus = pbuf_memcmp(p, i, mem, mem_len);
                if plus == 0 {
                    return i;
                }
            }
        }
    }
    0xFFFF
}

/// Find occurrence of `substr` with length `substr_len` in pbuf `p`, starting at offset
/// `start_offset`. WARNING: in contrast to strstr(), this one does not stop at the first
/// \0 in the pbuf/source string!
///
/// Returns 0xFFFF if substr was not found in p or the index where it was found.
///
/// # Safety
///
/// See the module's safety section; `p` is not null and `substr` is null or a
/// NUL-terminated string.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn pbuf_strstr(p: *const Pbuf, substr: *const c_char) -> u16 {
    // SAFETY: forwarded from the caller; `substr` is only read once known non-null.
    unsafe {
        if substr.is_null() || substr.read() == 0 || (*p).tot_len == 0xFFFF {
            return 0xFFFF;
        }
        let substr_len = crate::cstr::strlen(substr);
        if substr_len >= 0xFFFF {
            return 0xFFFF;
        }
        pbuf_memfind(p, substr.cast(), substr_len as u16, 0)
    }
}

#[cfg(all(test, feature = "mem", feature = "memp"))]
mod tests;
