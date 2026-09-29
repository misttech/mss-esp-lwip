// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/core/test_pbuf.c, plus edge cases of the functions it does not cover. The C
//! suite checks that no allocation leaks through lwIP's pool statistics; without them
//! (MEMP_MEM_MALLOC), each test frees what it allocates and the chain invariants are
//! checked instead.

extern crate std;

use core::ffi::c_void;
use std::vec::Vec;

use super::*;

/// The C tests' 1024 bytes: longer than one pool buffer, so a `PBUF_POOL` allocation is a
/// two-pbuf chain. Their configuration's pool buffers are 592 bytes; this one's are
/// `PBUF_POOL_BUFSIZE`, so the length follows it.
const CHAINED: u16 = PBUF_POOL_BUFSIZE_ALIGNED as u16 + 432;

/// Every pbuf of the chain at `p`, for the `tot_len` invariant.
fn chain(p: *mut Pbuf) -> Vec<*mut Pbuf> {
    let mut out = Vec::new();
    let mut q = p;
    while !q.is_null() {
        out.push(q);
        // SAFETY: a live chain.
        q = unsafe { (*q).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr) };
    }
    out
}

/// `p->tot_len == p->len + (p->next ? p->next->tot_len : 0)` for every pbuf of a packet.
fn assert_tot_len_invariant(p: *mut Pbuf) {
    for q in chain(p) {
        // SAFETY: a live chain.
        unsafe {
            let next = (*q).next.map_or(0, |n| (*n.as_ptr()).tot_len);
            assert_eq!((*q).tot_len, (*q).len + next);
        }
    }
}

fn payload<'a>(p: *mut Pbuf) -> &'a mut [u8] {
    // SAFETY: a live pbuf whose payload is `len` bytes and not otherwise borrowed.
    unsafe { core::slice::from_raw_parts_mut((*p).payload.cast::<u8>(), (*p).len.into()) }
}

/// A deterministic byte stream, for the large buffers (C uses rand()).
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (state >> 16) as u8
        })
        .collect()
}

#[test]
fn test_pbuf_alloc_zero_pbufs() {
    for type_ in [PBUF_ROM, PBUF_RAM, PBUF_REF, PBUF_POOL] {
        let p = pbuf_alloc(PBUF_RAW, 0, type_);
        assert!(!p.is_null(), "type {type_:#x}");
        // SAFETY: freshly allocated.
        unsafe { pbuf_free(p) };
    }
}

#[test]
fn test_pbuf_copy_zero_pbuf() {
    // SAFETY: every pbuf is freshly allocated and freed once.
    unsafe {
        let p1 = pbuf_alloc(PBUF_RAW, CHAINED, PBUF_RAM);
        assert!(!p1.is_null());
        assert_eq!((*p1).ref_, 1);

        let p2 = pbuf_alloc(PBUF_RAW, 2, PBUF_POOL);
        assert!(!p2.is_null());
        assert_eq!((*p2).ref_, 1);
        (*p2).len = 0;
        (*p2).tot_len = 0;

        pbuf_cat(p1, p2);
        assert_eq!((*p1).ref_, 1);
        assert_eq!((*p2).ref_, 1);

        let p3 = pbuf_alloc(PBUF_RAW, (*p1).tot_len, PBUF_POOL);
        let err = pbuf_copy(p3, p1);
        assert_eq!(err, ERR_VAL);

        pbuf_free(p1);
        pbuf_free(p3);
    }
}

#[test]
fn test_pbuf_copy_unmatched_chains() {
    // SAFETY: every pbuf is freshly allocated and freed once.
    unsafe {
        let mut source: *mut Pbuf = ptr::null_mut();
        // Build source pbuf from linked 16 byte parts, with payload bytes containing their
        // offset.
        for i in 0..8_u8 {
            let p = pbuf_alloc(PBUF_RAW, 16, PBUF_RAM);
            assert!(!p.is_null());
            for (j, byte) in payload(p).iter_mut().enumerate() {
                *byte = (i << 4) | j as u8;
            }
            if source.is_null() {
                source = p;
            } else {
                pbuf_cat(source, p);
            }
        }
        for i in 0..(*source).tot_len {
            assert_eq!(pbuf_get_at(source, i), i as u8);
        }

        // Build dest pbuf from other lengths.
        let dest = pbuf_alloc(PBUF_RAW, 35, PBUF_RAM);
        assert!(!dest.is_null());
        let p = pbuf_alloc(PBUF_RAW, 81, PBUF_RAM);
        assert!(!p.is_null());
        pbuf_cat(dest, p);
        let p = pbuf_alloc(PBUF_RAW, 27, PBUF_RAM);
        assert!(!p.is_null());
        pbuf_cat(dest, p);
        assert_tot_len_invariant(dest);

        // Copy contents and verify data.
        let err = pbuf_copy(dest, source);
        assert_eq!(err, ERR_OK);
        for i in 0..(*source).tot_len {
            assert_eq!(pbuf_get_at(dest, i), i as u8);
        }

        pbuf_free(source);
        pbuf_free(dest);
    }
}

#[test]
fn test_pbuf_copy_partial_pbuf() {
    let mut lwip = *b"lwip \0";
    let mut packet = *b"packet\0";
    let text = |p: *mut Pbuf| {
        // SAFETY: the payload is 14 bytes and holds a NUL.
        unsafe { core::ffi::CStr::from_ptr((*p).payload.cast()) }
            .to_str()
            .map(std::string::String::from)
            .unwrap()
    };
    // SAFETY: every pbuf is freshly allocated and freed once; the referenced payloads
    // outlive them.
    unsafe {
        let a = pbuf_alloc(PBUF_RAW, 5, PBUF_REF);
        assert!(!a.is_null());
        (*a).payload = lwip.as_mut_ptr().cast();
        let b = pbuf_alloc(PBUF_RAW, 7, PBUF_REF);
        assert!(!b.is_null());
        (*b).payload = packet.as_mut_ptr().cast();
        pbuf_cat(a, b);
        let dest = pbuf_alloc(PBUF_RAW, 14, PBUF_RAM);
        assert!(!dest.is_null());
        payload(dest).fill(0);

        // Don't copy if data will not fit.
        assert_eq!(pbuf_copy_partial_pbuf(dest, a, (*a).tot_len, 4), ERR_ARG);
        // Don't copy if length is longer than source.
        assert_eq!(
            pbuf_copy_partial_pbuf(dest, a, (*a).tot_len + 1, 0),
            ERR_ARG
        );
        // Normal copy.
        assert_eq!(pbuf_copy_partial_pbuf(dest, a, (*a).tot_len, 0), ERR_OK);
        assert_eq!(text(dest), "lwip packet");
        // Copy at offset.
        assert_eq!(pbuf_copy_partial_pbuf(dest, a, (*a).tot_len, 1), ERR_OK);
        assert_eq!(text(dest), "llwip packet");
        // Copy at offset with shorter length.
        assert_eq!(pbuf_copy_partial_pbuf(dest, a, 6, 6), ERR_OK);
        assert_eq!(text(dest), "llwip lwip p");
        // Copy with shorter length.
        assert_eq!(pbuf_copy_partial_pbuf(dest, a, 5, 0), ERR_OK);
        assert_eq!(text(dest), "lwip  lwip p");

        pbuf_free(dest);
        pbuf_free(a);
    }
}

#[test]
fn test_pbuf_split_64k_on_small_pbufs() {
    // SAFETY: freshly allocated and freed once.
    unsafe {
        let p = pbuf_alloc(PBUF_RAW, 1, PBUF_POOL);
        let mut rest = ptr::null_mut();
        pbuf_split_64k(p, &mut rest);
        assert_eq!((*p).tot_len, 1);
        assert!(rest.is_null());
        pbuf_free(p);
    }
}

#[test]
fn test_pbuf_queueing_bigger_than_64k() {
    const TESTBUFSIZE_1: usize = 65535;
    const TESTBUFSIZE_2: usize = 65530;
    const TESTBUFSIZE_3: usize = 50050;
    let testbuf_1 = pattern(TESTBUFSIZE_1, 1);
    let testbuf_2 = pattern(TESTBUFSIZE_2, 2);
    let testbuf_3 = pattern(TESTBUFSIZE_3, 3);
    let mut testbuf_1a = std::vec![0_u8; TESTBUFSIZE_1];
    let mut testbuf_2a = std::vec![0_u8; TESTBUFSIZE_2];
    let mut testbuf_3a = std::vec![0_u8; TESTBUFSIZE_3];

    // SAFETY: every pbuf is freshly allocated and freed once.
    unsafe {
        let p1 = pbuf_alloc(PBUF_RAW, TESTBUFSIZE_1 as u16, PBUF_POOL);
        assert!(!p1.is_null());
        let p2 = pbuf_alloc(PBUF_RAW, TESTBUFSIZE_2 as u16, PBUF_POOL);
        assert!(!p2.is_null());
        let p3 = pbuf_alloc(PBUF_RAW, TESTBUFSIZE_3 as u16, PBUF_POOL);
        assert!(!p3.is_null());
        assert_eq!(
            pbuf_take(p1, testbuf_1.as_ptr().cast(), TESTBUFSIZE_1 as u16),
            ERR_OK
        );
        assert_eq!(
            pbuf_take(p2, testbuf_2.as_ptr().cast(), TESTBUFSIZE_2 as u16),
            ERR_OK
        );
        assert_eq!(
            pbuf_take(p3, testbuf_3.as_ptr().cast(), TESTBUFSIZE_3 as u16),
            ERR_OK
        );

        pbuf_cat(p1, p2);
        pbuf_cat(p1, p3);

        let mut rest2 = ptr::null_mut();
        pbuf_split_64k(p1, &mut rest2);
        assert_eq!(usize::from((*p1).tot_len), TESTBUFSIZE_1);
        assert_eq!(
            (*rest2).tot_len,
            ((TESTBUFSIZE_2 + TESTBUFSIZE_3) & 0xFFFF) as u16
        );
        let mut rest3 = ptr::null_mut();
        pbuf_split_64k(rest2, &mut rest3);
        assert_eq!(usize::from((*rest2).tot_len), TESTBUFSIZE_2);
        assert_eq!(usize::from((*rest3).tot_len), TESTBUFSIZE_3);

        pbuf_copy_partial(p1, testbuf_1a.as_mut_ptr().cast(), TESTBUFSIZE_1 as u16, 0);
        pbuf_copy_partial(
            rest2,
            testbuf_2a.as_mut_ptr().cast(),
            TESTBUFSIZE_2 as u16,
            0,
        );
        pbuf_copy_partial(
            rest3,
            testbuf_3a.as_mut_ptr().cast(),
            TESTBUFSIZE_3 as u16,
            0,
        );
        assert_eq!(testbuf_1, testbuf_1a);
        assert_eq!(testbuf_2, testbuf_2a);
        assert_eq!(testbuf_3, testbuf_3a);

        pbuf_free(p1);
        pbuf_free(rest2);
        pbuf_free(rest3);
    }
}

#[test]
fn test_pbuf_take_at_edge() {
    let testdata = [0x01_u8, 0x08, 0x82, 0x02];
    let n = testdata.len() as u16;
    let data: *const c_void = testdata.as_ptr().cast();
    // SAFETY: freshly allocated and freed once.
    unsafe {
        // Alloc big enough to get a chain of pbufs.
        let p = pbuf_alloc(PBUF_RAW, CHAINED, PBUF_POOL);
        let q = (*p).next.unwrap().as_ptr();
        assert_ne!((*p).tot_len, (*p).len);
        payload(p).fill(0);
        payload(q).fill(0);

        // Copy data to the beginning of first pbuf.
        assert_eq!(pbuf_take_at(p, data, n, 0), ERR_OK);
        assert_eq!(&payload(p)[..4], &testdata);

        // Copy data to the just before end of first pbuf.
        let len = (*p).len;
        assert_eq!(pbuf_take_at(p, data, n, len - 1), ERR_OK);
        assert_eq!(payload(p)[usize::from(len) - 1], testdata[0]);
        assert_eq!(&payload(q)[..3], &testdata[1..]);

        // Copy data to the beginning of second pbuf.
        assert_eq!(pbuf_take_at(p, data, n, len), ERR_OK);
        assert_eq!(&payload(p)[..4], &testdata);
        pbuf_free(p);
    }
}

#[test]
fn test_pbuf_get_put_at_edge() {
    let testdata = 0x01_u8;
    // SAFETY: freshly allocated and freed once.
    unsafe {
        // Alloc big enough to get a chain of pbufs.
        let p = pbuf_alloc(PBUF_RAW, CHAINED, PBUF_POOL);
        let q = (*p).next.unwrap().as_ptr();
        assert_ne!((*p).tot_len, (*p).len);
        payload(p).fill(0);
        payload(q).fill(0);

        // Put byte at the beginning of second pbuf.
        pbuf_put_at(p, (*p).len, testdata);
        assert_eq!(payload(q)[0], testdata);
        assert_eq!(pbuf_get_at(p, (*p).len), payload(q)[0]);
        pbuf_free(p);
    }
}

// Beyond test_pbuf.c.

#[test]
fn pool_chains_split_at_the_pool_buffer_size_and_keep_the_invariant() {
    // SAFETY: freshly allocated and freed once.
    unsafe {
        let p = pbuf_alloc(40, 4000, PBUF_POOL);
        assert_tot_len_invariant(p);
        let pbufs = chain(p);
        assert_eq!(pbufs.len(), 3);
        // The first pbuf leaves the layer's header room in front of its payload.
        assert_eq!(usize::from((*pbufs[0]).len), PBUF_POOL_BUFSIZE_ALIGNED - 40);
        assert_eq!(usize::from((*pbufs[1]).len), PBUF_POOL_BUFSIZE_ALIGNED);
        for &q in &pbufs {
            assert_eq!((*q).payload.addr() % config::MEM_ALIGNMENT, 0);
            assert_eq!((*q).type_internal, PBUF_POOL as u8);
        }
        assert_eq!(pbuf_clen(p), 3);
        assert_eq!(pbuf_free(p), 3);
    }
}

#[test]
fn headers_move_within_the_room_they_were_allocated_with() {
    // SAFETY: freshly allocated and freed once.
    unsafe {
        let p = pbuf_alloc(14, 100, PBUF_RAM);
        let start = (*p).payload;
        // There is room for the 14-byte header (rounded up), but not a byte more.
        assert_eq!(pbuf_add_header(p, 14), 0);
        assert_eq!((*p).len, 114);
        assert_eq!(pbuf_remove_header(p, 14), 0);
        assert_eq!((*p).payload, start);
        assert_eq!(pbuf_add_header(p, 17), 1, "past the start of the buffer");
        assert_eq!(pbuf_remove_header(p, 101), 1, "past the end of the pbuf");
        assert_eq!(pbuf_header(p, -10), 0);
        assert_eq!((*p).len, 90);
        assert_eq!(pbuf_header(p, 10), 0);
        assert_eq!(pbuf_add_header(p, 0x1_0000), 1, "more than 64k");
        assert_eq!(pbuf_add_header(p, 0), 0);
        pbuf_free(p);

        // A reference pbuf's payload can move to the front only when forced.
        let mut data = [0_u8; 32];
        let r = pbuf_alloc_reference(data.as_mut_ptr().add(8).cast(), 16, PBUF_REF);
        assert_eq!(pbuf_add_header(r, 4), 1);
        assert_eq!(pbuf_header_force(r, 4), 0);
        assert_eq!((*r).payload, data.as_mut_ptr().add(4).cast());
        // tot_len may not wrap.
        (*r).tot_len = 0xFFFE;
        assert_eq!(pbuf_add_header_force(r, 4), 1);
        pbuf_free(r);
    }
}

#[test]
fn realloc_shrinks_and_frees_the_tail() {
    // SAFETY: freshly allocated and freed once.
    unsafe {
        let p = pbuf_alloc(PBUF_RAW, 4000, PBUF_POOL);
        let first = (*p).len;
        pbuf_realloc(p, first + 10);
        assert_tot_len_invariant(p);
        assert_eq!(pbuf_clen(p), 2);
        assert_eq!((*p).tot_len, first + 10);
        // Growing is not supported: nothing changes.
        pbuf_realloc(p, 5000);
        assert_eq!((*p).tot_len, first + 10);
        pbuf_realloc(p, 3);
        assert_eq!(pbuf_clen(p), 1);
        assert_eq!(((*p).len, (*p).tot_len), (3, 3));
        pbuf_free(p);

        let r = pbuf_alloc(PBUF_RAW, 100, PBUF_RAM);
        pbuf_realloc(r, 60);
        assert_eq!(((*r).len, (*r).tot_len), (60, 60));
        pbuf_free(r);
    }
}

#[test]
fn references_keep_chains_alive_until_the_last_free() {
    // SAFETY: freshly allocated; each reference is released once.
    unsafe {
        let h = pbuf_alloc(PBUF_RAW, 10, PBUF_RAM);
        let t = pbuf_alloc(PBUF_RAW, 20, PBUF_RAM);
        pbuf_chain(h, t);
        assert_eq!((*t).ref_, 2);
        assert_eq!((*h).tot_len, 30);
        // Freeing the head frees only the head: the tail is still referenced.
        assert_eq!(pbuf_free(h), 1);
        assert_eq!((*t).ref_, 1);
        assert_eq!(pbuf_free(t), 1);

        let h = pbuf_alloc(PBUF_RAW, 10, PBUF_RAM);
        let t = pbuf_alloc(PBUF_RAW, 20, PBUF_RAM);
        pbuf_ref(t);
        pbuf_cat(h, t);
        // The tail survives the dechain: the caller's reference remains.
        let rest = pbuf_dechain(h);
        assert_eq!(rest, t);
        assert_eq!((*h).tot_len, 10);
        assert_eq!(pbuf_free(t), 1);
        assert!(pbuf_dechain(h).is_null(), "nothing to dechain");
        assert_eq!(pbuf_free(h), 1);
    }
}

#[test]
fn free_header_drops_whole_pbufs_then_trims() {
    // SAFETY: freshly allocated and freed once.
    unsafe {
        let p = pbuf_alloc(PBUF_RAW, 10, PBUF_RAM);
        let q = pbuf_alloc(PBUF_RAW, 20, PBUF_RAM);
        pbuf_cat(p, q);
        let rest = pbuf_free_header(p, 15);
        assert_eq!(rest, q);
        assert_eq!(((*q).len, (*q).tot_len), (15, 15));
        assert!(pbuf_free_header(q, 15).is_null());
    }
}

#[test]
fn custom_pbufs_are_freed_through_their_function() {
    static FREED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    unsafe extern "C" fn free_custom(p: *mut Pbuf) {
        FREED.store(p.addr(), Relaxed);
    }
    let mut custom = core::mem::MaybeUninit::<PbufCustom>::uninit();
    let mut memory = [0_u32; 32];
    // SAFETY: the custom pbuf and its memory outlive it; it is freed once.
    unsafe {
        ptr::addr_of_mut!((*custom.as_mut_ptr()).custom_free_function).write(Some(free_custom));
        // Too small for the header room and the payload.
        assert!(
            pbuf_alloced_custom(
                20,
                120,
                PBUF_REF,
                custom.as_mut_ptr(),
                memory.as_mut_ptr().cast(),
                128
            )
            .is_null()
        );
        let p = pbuf_alloced_custom(
            20,
            100,
            PBUF_REF,
            custom.as_mut_ptr(),
            memory.as_mut_ptr().cast(),
            128,
        );
        assert_eq!(p, custom.as_mut_ptr().cast());
        assert_eq!((*p).flags, PBUF_FLAG_IS_CUSTOM);
        assert_eq!(
            (*p).payload,
            memory.as_mut_ptr().cast::<u8>().add(20).cast()
        );
        // A custom PBUF_RAM is not trimmed; this one only shrinks its lengths.
        pbuf_realloc(p, 50);
        assert_eq!((*p).len, 50);
        assert_eq!(pbuf_free(p), 1);
        assert_eq!(FREED.load(Relaxed), p.addr());
    }
}

#[test]
fn byte_access_and_search_span_pbufs() {
    // SAFETY: freshly allocated and freed once.
    unsafe {
        let p = pbuf_alloc(PBUF_RAW, 8, PBUF_RAM);
        let q = pbuf_alloc(PBUF_RAW, 8, PBUF_RAM);
        payload(p).copy_from_slice(b"GET / HT");
        payload(q).copy_from_slice(b"TP/1.0\r\n");
        pbuf_cat(p, q);

        assert_eq!(pbuf_try_get_at(p, 15), c_int::from(b'\n'));
        assert_eq!(pbuf_try_get_at(p, 16), -1);
        assert_eq!(pbuf_get_at(p, 16), 0);
        pbuf_put_at(p, 16, 0xff);

        assert_eq!(pbuf_memcmp(p, 6, b"HTTP".as_ptr().cast(), 4), 0);
        assert_eq!(
            pbuf_memcmp(p, 6, b"HTTX".as_ptr().cast(), 4),
            4,
            "diffoffset + 1"
        );
        assert_eq!(
            pbuf_memcmp(p, 14, b"\r\n!".as_ptr().cast(), 3),
            0xffff,
            "too short"
        );
        assert_eq!(pbuf_memfind(p, b"HTTP".as_ptr().cast(), 4, 0), 6);
        assert_eq!(pbuf_memfind(p, b"HTTP".as_ptr().cast(), 4, 7), 0xFFFF);
        assert_eq!(pbuf_strstr(p, c"1.0".as_ptr()), 11);
        assert_eq!(pbuf_strstr(p, c"".as_ptr()), 0xFFFF);
        assert_eq!(pbuf_strstr(p, ptr::null()), 0xFFFF);

        // Contiguous bytes: zero-copy inside one pbuf, copied across two.
        let mut buffer = [0_u8; 8];
        let inside = pbuf_get_contiguous(p, buffer.as_mut_ptr().cast(), 8, 4, 0);
        assert_eq!(inside, (*p).payload);
        let across = pbuf_get_contiguous(p, buffer.as_mut_ptr().cast(), 8, 6, 5);
        assert_eq!(across, buffer.as_mut_ptr().cast());
        assert_eq!(&buffer[..6], b" HTTP/");
        assert!(pbuf_get_contiguous(p, buffer.as_mut_ptr().cast(), 4, 6, 5).is_null());

        let mut skipped = 0;
        assert_eq!(pbuf_skip(p, 10, &mut skipped), q);
        assert_eq!(skipped, 2);
        assert!(pbuf_skip(p, 16, ptr::null_mut()).is_null());

        // Coalescing copies the chain into one PBUF_RAM pbuf and frees the chain.
        let one = pbuf_coalesce(p, PBUF_RAW);
        assert_eq!(pbuf_clen(one), 1);
        assert_eq!(payload(one), b"GET / HTTP/1.0\r\n");
        pbuf_free(one);
    }
}

#[test]
fn take_and_copy_partial_check_their_bounds() {
    let data = pattern(40, 9);
    let mut out = [0_u8; 40];
    // SAFETY: freshly allocated and freed once.
    unsafe {
        let p = pbuf_alloc(PBUF_RAW, 30, PBUF_RAM);
        assert_eq!(pbuf_take(p, data.as_ptr().cast(), 40), ERR_MEM);
        assert_eq!(pbuf_take(ptr::null_mut(), data.as_ptr().cast(), 1), ERR_ARG);
        assert_eq!(pbuf_take(p, ptr::null(), 1), ERR_ARG);
        assert_eq!(pbuf_take(p, data.as_ptr().cast(), 30), ERR_OK);
        assert_eq!(pbuf_take_at(p, data.as_ptr().cast(), 10, 25), ERR_MEM);
        assert_eq!(pbuf_copy_partial(p, out.as_mut_ptr().cast(), 40, 10), 20);
        assert_eq!(&out[..20], &data[10..30]);
        assert_eq!(pbuf_copy_partial(p, ptr::null_mut(), 4, 0), 0);
        assert_eq!(pbuf_copy(p, ptr::null()), ERR_ARG);
        pbuf_free(p);
    }
}

#[test]
fn an_empty_pool_queues_the_ooseq_callback_once_it_can() {
    // The tcpip queue stand-in refuses the call, so the pending flag is cleared again.
    pbuf_pool_is_empty();
    assert_eq!(pbuf_free_ooseq_pending.load(Relaxed), 0);
    pbuf_free_ooseq();
}
