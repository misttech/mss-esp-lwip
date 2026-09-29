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

//! Internet checksum functions, from `src/core/inet_chksum.c`.
//!
//! `lwip_standard_chksum` is the port's `LWIP_CHKSUM` unless it names its own; of the
//! three C algorithms, this is #2 (the default, which ESP-IDF uses): IP checksum two bytes
//! at a time with support for unaligned buffer, by Curt McDowell, Broadcom Corp.
//! 12/08/2005. `build.rs` refuses the others.

#[cfg(lwip_ipv4)]
use crate::types::Ip4Addr;
#[cfg(lwip_ipv6)]
use crate::types::Ip6Addr;
#[cfg(any(lwip_ipv4, lwip_ipv6))]
use crate::types::IpAddr;
use crate::types::{Pbuf, pbuf_chain};

/// `FOLD_U32T(u)`: add the upper 16 bits of `u` into the lower 16.
fn fold_u32(u: u32) -> u32 {
    (u >> 16) + (u & 0x0000_ffff)
}

/// `SWAP_BYTES_IN_WORD(w)`: swap the two low bytes of `w`, dropping the rest.
fn swap_bytes_in_word(w: u32) -> u32 {
    ((w & 0xff) << 8) | ((w & 0xff00) >> 8)
}

/// `lwip_htons()`, as the C stack calls it.
fn htons(n: u16) -> u16 {
    n.to_be()
}

/// The lwip checksum of `data`, which may start at any boundary: the host order (!),
/// non-inverted Internet sum. Works for lengths up to and including 0x20000.
///
/// The words are summed as the host reads them from `data`'s own alignment, so a buffer
/// at an odd address is summed from its second byte and the result swapped, exactly as
/// the C code does; the checksum does not depend on the host's byte order.
pub fn standard_chksum(data: &[u8]) -> u16 {
    let mut t = [0_u8; 2];
    let mut sum: u32 = 0;
    let odd = data.as_ptr().addr() & 1 != 0;
    let mut rest = data;

    // Get aligned to u16_t.
    if odd && let Some((&first, tail)) = rest.split_first() {
        t[1] = first;
        rest = tail;
    }

    // Add the bulk of the data.
    let (words, left_over) = rest.as_chunks::<2>();
    for &word in words {
        sum = sum.wrapping_add(u32::from(u16::from_ne_bytes(word)));
    }

    // Consume left-over byte, if any.
    if let [last] = left_over {
        t[0] = *last;
    }

    // Add end bytes.
    sum = sum.wrapping_add(u32::from(u16::from_ne_bytes(t)));

    // Fold 32-bit sum to 16 bits; calling this twice is probably faster than if
    // statements...
    sum = fold_u32(sum);
    sum = fold_u32(sum);

    // Swap if alignment was odd.
    if odd {
        sum = swap_bytes_in_word(sum);
    }

    sum as u16
}

/// `lwip_standard_chksum()`: [`standard_chksum`] for C. A `len` of 0 or less sums
/// nothing.
///
/// # Safety
///
/// `dataptr` is readable for `len` bytes.
#[cfg(lwip_standard_chksum)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn lwip_standard_chksum(dataptr: *const core::ffi::c_void, len: i32) -> u16 {
    // SAFETY: forwarded from the caller.
    standard_chksum(unsafe { bytes(dataptr, usize::try_from(len).unwrap_or(0)) })
}

/// The `len` bytes at `dataptr`, which is only read when `len` is not 0.
///
/// # Safety
///
/// `dataptr` is readable for `len` bytes and not written while the slice lives.
unsafe fn bytes<'a>(dataptr: *const core::ffi::c_void, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: readable for `len` bytes, per the caller.
    unsafe { core::slice::from_raw_parts(dataptr.cast::<u8>(), len) }
}

/// The checksum of a pbuf's payload, as `LWIP_CHKSUM(q->payload, len)`.
fn pbuf_chksum(q: &Pbuf, len: usize) -> u16 {
    // SAFETY: a pbuf in a chain the stack hands over has `len` readable payload bytes.
    let payload = unsafe { q.payload_bytes() };
    standard_chksum(payload.get(..len).unwrap_or(payload))
}

/// Parts of the pseudo checksum which are common to IPv4 and IPv6.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain.
#[cfg(any(lwip_ipv4, lwip_ipv6))]
unsafe fn inet_cksum_pseudo_base(p: *const Pbuf, proto: u8, proto_len: u16, mut acc: u32) -> u16 {
    let mut swapped = false;

    // Iterate through all pbuf in chain.
    // SAFETY: forwarded from the caller.
    for q in unsafe { pbuf_chain(p) } {
        acc = acc.wrapping_add(u32::from(pbuf_chksum(q, usize::from(q.len))));
        // Just executing this next line is probably faster that the if statement needed
        // to check whether we really need to execute it, and does no harm.
        acc = fold_u32(acc);
        if q.len % 2 != 0 {
            swapped = !swapped;
            acc = swap_bytes_in_word(acc);
        }
    }

    if swapped {
        acc = swap_bytes_in_word(acc);
    }

    acc = acc.wrapping_add(u32::from(htons(u16::from(proto))));
    acc = acc.wrapping_add(u32::from(htons(proto_len)));

    // Fold 32-bit sum to 16 bits; calling this twice is probably faster than if
    // statements...
    acc = fold_u32(acc);
    acc = fold_u32(acc);
    !(acc & 0xffff) as u16
}

/// The IPv4 part of the pseudo header, `src` and `dest` folded down to 16 bits.
#[cfg(lwip_ipv4)]
fn ip4_pseudo_acc(src: &Ip4Addr, dest: &Ip4Addr) -> u32 {
    let mut addr = src.addr;
    let mut acc = addr & 0xffff;
    acc = acc.wrapping_add((addr >> 16) & 0xffff);
    addr = dest.addr;
    acc = acc.wrapping_add(addr & 0xffff);
    acc = acc.wrapping_add((addr >> 16) & 0xffff);
    // Fold down to 16 bits.
    acc = fold_u32(acc);
    fold_u32(acc)
}

/// The IPv6 part of the pseudo header, `src` and `dest` folded down to 16 bits.
#[cfg(lwip_ipv6)]
fn ip6_pseudo_acc(src: &Ip6Addr, dest: &Ip6Addr) -> u32 {
    let mut acc: u32 = 0;
    for (&s, &d) in src.addr.iter().zip(&dest.addr) {
        acc = acc.wrapping_add(s & 0xffff);
        acc = acc.wrapping_add((s >> 16) & 0xffff);
        acc = acc.wrapping_add(d & 0xffff);
        acc = acc.wrapping_add((d >> 16) & 0xffff);
    }
    // Fold down to 16 bits.
    acc = fold_u32(acc);
    fold_u32(acc)
}

/// Calculates the IPv4 pseudo Internet checksum used by TCP and UDP for a pbuf chain. IP
/// addresses are expected to be in network byte order.
///
/// Returns the checksum to be saved directly in the protocol header.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain; `src` and `dest` are valid.
#[cfg(lwip_ipv4)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_chksum_pseudo(
    p: *mut Pbuf,
    proto: u8,
    proto_len: u16,
    src: *const Ip4Addr,
    dest: *const Ip4Addr,
) -> u16 {
    // SAFETY: valid, per the caller.
    let acc = unsafe { ip4_pseudo_acc(&*src, &*dest) };
    // SAFETY: forwarded from the caller.
    unsafe { inet_cksum_pseudo_base(p, proto, proto_len, acc) }
}

/// Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a pbuf chain.
/// IPv6 addresses are expected to be in network byte order.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain; `src` and `dest` are valid.
#[cfg(lwip_ipv6)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip6_chksum_pseudo(
    p: *mut Pbuf,
    proto: u8,
    proto_len: u16,
    src: *const Ip6Addr,
    dest: *const Ip6Addr,
) -> u16 {
    // SAFETY: valid, per the caller.
    let acc = unsafe { ip6_pseudo_acc(&*src, &*dest) };
    // SAFETY: forwarded from the caller.
    unsafe { inet_cksum_pseudo_base(p, proto, proto_len, acc) }
}

/// Calculates the IPv4 or IPv6 pseudo Internet checksum used by TCP and UDP for a pbuf
/// chain, by the type of `dest`. IP addresses are expected to be in network byte order.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain; `src` and `dest` are valid.
#[cfg(any(lwip_ipv4, lwip_ipv6))]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip_chksum_pseudo(
    p: *mut Pbuf,
    proto: u8,
    proto_len: u16,
    src: *const IpAddr,
    dest: *const IpAddr,
) -> u16 {
    // SAFETY: valid, per the caller.
    let (src, dest) = unsafe { (&*src, &*dest) };
    #[cfg(all(lwip_ipv4, lwip_ipv6))]
    let acc = if dest.is_v6() {
        ip6_pseudo_acc(src.ip6(), dest.ip6())
    } else {
        ip4_pseudo_acc(src.ip4(), dest.ip4())
    };
    #[cfg(all(lwip_ipv4, not(lwip_ipv6)))]
    let acc = ip4_pseudo_acc(src, dest);
    #[cfg(all(lwip_ipv6, not(lwip_ipv4)))]
    let acc = ip6_pseudo_acc(src, dest);
    // SAFETY: forwarded from the caller.
    unsafe { inet_cksum_pseudo_base(p, proto, proto_len, acc) }
}

/// Parts of the pseudo checksum which are common to IPv4 and IPv6, over the first
/// `chksum_len` bytes of the chain.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain.
#[cfg(any(lwip_ipv4, lwip_ipv6))]
unsafe fn inet_cksum_pseudo_partial_base(
    p: *const Pbuf,
    proto: u8,
    proto_len: u16,
    mut chksum_len: u16,
    mut acc: u32,
) -> u16 {
    let mut swapped = false;

    // Iterate through all pbuf in chain.
    // SAFETY: forwarded from the caller.
    for q in unsafe { pbuf_chain(p) } {
        if chksum_len == 0 {
            break;
        }
        let chklen = q.len.min(chksum_len);
        acc = acc.wrapping_add(u32::from(pbuf_chksum(q, usize::from(chklen))));
        chksum_len -= chklen;
        lwip_assert!("delete me", chksum_len < 0x7fff);
        // Fold the upper bit down.
        acc = fold_u32(acc);
        if q.len % 2 != 0 {
            swapped = !swapped;
            acc = swap_bytes_in_word(acc);
        }
    }

    if swapped {
        acc = swap_bytes_in_word(acc);
    }

    acc = acc.wrapping_add(u32::from(htons(u16::from(proto))));
    acc = acc.wrapping_add(u32::from(htons(proto_len)));

    // Fold 32-bit sum to 16 bits; calling this twice is probably faster than if
    // statements...
    acc = fold_u32(acc);
    acc = fold_u32(acc);
    !(acc & 0xffff) as u16
}

/// Calculates the IPv4 pseudo Internet checksum used by TCP and UDP for the first
/// `chksum_len` bytes of a pbuf chain. IP addresses are expected to be in network byte
/// order.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain; `src` and `dest` are valid.
#[cfg(lwip_ipv4)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_chksum_pseudo_partial(
    p: *mut Pbuf,
    proto: u8,
    proto_len: u16,
    chksum_len: u16,
    src: *const Ip4Addr,
    dest: *const Ip4Addr,
) -> u16 {
    // SAFETY: valid, per the caller.
    let acc = unsafe { ip4_pseudo_acc(&*src, &*dest) };
    // SAFETY: forwarded from the caller.
    unsafe { inet_cksum_pseudo_partial_base(p, proto, proto_len, chksum_len, acc) }
}

/// Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a pbuf chain.
/// IPv6 addresses are expected to be in network byte order. Will only compute for a
/// portion of the payload, its first `chksum_len` bytes.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain; `src` and `dest` are valid.
#[cfg(lwip_ipv6)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip6_chksum_pseudo_partial(
    p: *mut Pbuf,
    proto: u8,
    proto_len: u16,
    chksum_len: u16,
    src: *const Ip6Addr,
    dest: *const Ip6Addr,
) -> u16 {
    // SAFETY: valid, per the caller.
    let acc = unsafe { ip6_pseudo_acc(&*src, &*dest) };
    // SAFETY: forwarded from the caller.
    unsafe { inet_cksum_pseudo_partial_base(p, proto, proto_len, chksum_len, acc) }
}

/// Calculates the IPv4 or IPv6 pseudo Internet checksum used by TCP and UDP for the first
/// `chksum_len` bytes of a pbuf chain, by the type of `dest`.
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain; `src` and `dest` are valid.
#[cfg(any(lwip_ipv4, lwip_ipv6))]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip_chksum_pseudo_partial(
    p: *mut Pbuf,
    proto: u8,
    proto_len: u16,
    chksum_len: u16,
    src: *const IpAddr,
    dest: *const IpAddr,
) -> u16 {
    // SAFETY: valid, per the caller.
    let (src, dest) = unsafe { (&*src, &*dest) };
    #[cfg(all(lwip_ipv4, lwip_ipv6))]
    let acc = if dest.is_v6() {
        ip6_pseudo_acc(src.ip6(), dest.ip6())
    } else {
        ip4_pseudo_acc(src.ip4(), dest.ip4())
    };
    #[cfg(all(lwip_ipv4, not(lwip_ipv6)))]
    let acc = ip4_pseudo_acc(src, dest);
    #[cfg(all(lwip_ipv6, not(lwip_ipv4)))]
    let acc = ip6_pseudo_acc(src, dest);
    // SAFETY: forwarded from the caller.
    unsafe { inet_cksum_pseudo_partial_base(p, proto, proto_len, chksum_len, acc) }
}

/// Calculates the Internet checksum over a portion of memory. Used primarily for IP and
/// ICMP. `dataptr` needs no alignment.
///
/// Returns the checksum to be saved directly in the protocol header.
///
/// # Safety
///
/// `dataptr` is readable for `len` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_chksum(dataptr: *const core::ffi::c_void, len: u16) -> u16 {
    // SAFETY: forwarded from the caller.
    !standard_chksum(unsafe { bytes(dataptr, usize::from(len)) })
}

/// Calculate a checksum over a chain of pbufs (without pseudo-header, much like
/// `inet_chksum` only pbufs are used).
///
/// # Safety
///
/// `p` is null or a well-formed pbuf chain.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn inet_chksum_pbuf(p: *mut Pbuf) -> u16 {
    let mut acc: u32 = 0;
    let mut swapped = false;

    // SAFETY: forwarded from the caller.
    for q in unsafe { pbuf_chain(p) } {
        acc = acc.wrapping_add(u32::from(pbuf_chksum(q, usize::from(q.len))));
        acc = fold_u32(acc);
        if q.len % 2 != 0 {
            swapped = !swapped;
            acc = swap_bytes_in_word(acc);
        }
    }

    if swapped {
        acc = swap_bytes_in_word(acc);
    }
    !(acc & 0xffff) as u16
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr::{self, NonNull};
    use std::vec::Vec;

    use super::*;

    /// RFC 1071's reference: the non-inverted ones' complement sum of big-endian 16-bit
    /// words, as a network-order value read back in host order.
    fn reference(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in data.chunks(2) {
            let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        (sum as u16).to_be()
    }

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
    fn standard_chksum_matches_rfc1071_at_every_alignment_and_length() {
        let data = pattern(600, 7);
        for start in 0..4 {
            for len in [0, 1, 2, 3, 20, 21, 64, 65, 511, 596] {
                let slice = &data[start..start + len];
                assert_eq!(
                    standard_chksum(slice),
                    reference(slice),
                    "start {start} len {len}"
                );
            }
        }
    }

    #[test]
    fn standard_chksum_of_all_ones_does_not_fold_to_zero() {
        assert_eq!(standard_chksum(&[0xff; 64]), 0xffff);
        assert_eq!(standard_chksum(&[]), 0);
    }

    #[test]
    fn inet_chksum_of_a_valid_ip_header_verifies_to_zero() {
        // An IPv4 header with its checksum (0xb861) in place.
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        // SAFETY: a live array.
        assert_eq!(unsafe { inet_chksum(header.as_ptr().cast(), 20) }, 0);
        let mut zeroed = header;
        zeroed[10] = 0;
        zeroed[11] = 0;
        // SAFETY: a live array.
        let sum = unsafe { inet_chksum(zeroed.as_ptr().cast(), 20) };
        assert_eq!(sum.to_ne_bytes(), [0xb8, 0x61]);
    }

    fn pbuf(payload: &mut [u8], next: Option<NonNull<Pbuf>>) -> Pbuf {
        Pbuf {
            next,
            payload: payload.as_mut_ptr().cast(),
            tot_len: 0,
            len: payload.len() as u16,
            type_internal: 0,
            flags: 0,
            ref_: 1,
            if_idx: 0,
        }
    }

    /// Split `data` into a chain at `cuts` and return the chain's checksum.
    fn chain_chksum(data: &mut [u8], cuts: &[usize]) -> u16 {
        let mut pieces = Vec::new();
        let mut rest = data;
        let mut last = 0;
        for &cut in cuts {
            let (head, tail) = rest.split_at_mut(cut - last);
            pieces.push(head);
            rest = tail;
            last = cut;
        }
        pieces.push(rest);
        let mut pbufs: Vec<Pbuf> = pieces.into_iter().map(|piece| pbuf(piece, None)).collect();
        for i in (0..pbufs.len() - 1).rev() {
            let next = NonNull::from(&mut pbufs[i + 1]);
            pbufs[i].next = Some(next);
        }
        // SAFETY: a well-formed chain over live buffers.
        unsafe { inet_chksum_pbuf(&mut pbufs[0]) }
    }

    #[test]
    fn a_chain_sums_like_one_buffer_wherever_it_is_cut() {
        let mut data = pattern(301, 3);
        let whole = !reference(&data);
        for cuts in [&[][..], &[1], &[2], &[1, 2], &[7, 8, 100], &[150, 151, 300]] {
            assert_eq!(chain_chksum(&mut data, cuts), whole, "cuts {cuts:?}");
        }
        // SAFETY: a null chain has nothing to sum.
        assert_eq!(unsafe { inet_chksum_pbuf(ptr::null_mut()) }, 0xffff);
    }

    #[cfg(lwip_ipv4)]
    #[test]
    fn udp_pseudo_checksum_matches_a_captured_datagram() {
        // DHCP DISCOVER-sized UDP header plus payload from 0.0.0.0 to 255.255.255.255;
        // the reference sums the pseudo header and the segment in one pass.
        let mut segment = pattern(28, 11);
        segment[6] = 0;
        segment[7] = 0;
        let src = Ip4Addr { addr: 0 };
        let dest = Ip4Addr { addr: 0xffff_ffff };
        let mut pseudo = Vec::new();
        pseudo.extend(src.addr.to_ne_bytes());
        pseudo.extend(dest.addr.to_ne_bytes());
        pseudo.extend([0, 17]);
        pseudo.extend((segment.len() as u16).to_be_bytes());
        pseudo.extend(&segment);
        let expected = !reference(&pseudo);
        let mut p = pbuf(&mut segment, None);
        // SAFETY: a one-pbuf chain over a live buffer; valid addresses.
        let sum = unsafe { inet_chksum_pseudo(&mut p, 17, 28, &src, &dest) };
        assert_eq!(sum, expected);
        // The partial checksum over the whole segment is the same.
        // SAFETY: as above.
        let partial = unsafe { inet_chksum_pseudo_partial(&mut p, 17, 28, 28, &src, &dest) };
        assert_eq!(partial, expected);
    }

    #[cfg(all(lwip_ipv4, lwip_ipv6))]
    #[test]
    fn ip_chksum_pseudo_follows_the_destination_type() {
        let mut segment = pattern(40, 5);
        let mut p = pbuf(&mut segment, None);
        let v4_src = IpAddr::v4(0x0100_a8c0);
        let v4_dest = IpAddr::v4(0x0200_a8c0);
        // SAFETY: a one-pbuf chain over a live buffer; valid addresses.
        unsafe {
            assert_eq!(
                ip_chksum_pseudo(&mut p, 6, 40, &v4_src, &v4_dest),
                inet_chksum_pseudo(&mut p, 6, 40, v4_src.ip4(), v4_dest.ip4())
            );
        }
        let mut v6_src = IpAddr::v4(0);
        let mut v6_dest = IpAddr::v4(0);
        v6_src.u_addr.ip6 = Ip6Addr {
            addr: [0x80fe, 0, 0x1100_0000, 0x2200_0000],
            ..Default::default()
        };
        v6_dest.u_addr.ip6 = Ip6Addr {
            addr: [0x80fe, 0, 0x3300_0000, 0x4400_0000],
            ..Default::default()
        };
        v6_src.type_ = crate::types::IPADDR_TYPE_V6;
        v6_dest.type_ = crate::types::IPADDR_TYPE_V6;
        let mut pseudo = Vec::new();
        for word in v6_src.ip6().addr.iter().chain(&v6_dest.ip6().addr) {
            pseudo.extend(word.to_ne_bytes());
        }
        pseudo.extend([0, 0, 0, 40, 0, 0, 0, 6]);
        pseudo.extend(&segment);
        let expected = !reference(&pseudo);
        let mut p = pbuf(&mut segment, None);
        // SAFETY: as above.
        unsafe {
            assert_eq!(ip_chksum_pseudo(&mut p, 6, 40, &v6_src, &v6_dest), expected);
            assert_eq!(
                ip6_chksum_pseudo(&mut p, 6, 40, v6_src.ip6(), v6_dest.ip6()),
                expected
            );
            assert_eq!(
                ip_chksum_pseudo_partial(&mut p, 6, 40, 40, &v6_src, &v6_dest),
                expected
            );
        }
    }

    #[cfg(lwip_ipv4)]
    #[test]
    fn a_partial_checksum_covers_only_its_prefix() {
        let mut segment = pattern(64, 9);
        let src = Ip4Addr { addr: 0x0100_000a };
        let dest = Ip4Addr { addr: 0x0200_000a };
        let mut head = segment[..30].to_vec();
        let mut p_head = pbuf(&mut head, None);
        let mut p = pbuf(&mut segment, None);
        // SAFETY: one-pbuf chains over live buffers; valid addresses.
        unsafe {
            assert_eq!(
                inet_chksum_pseudo_partial(&mut p, 6, 64, 30, &src, &dest),
                inet_chksum_pseudo_partial(&mut p_head, 6, 64, 30, &src, &dest)
            );
        }
    }
}
