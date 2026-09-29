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

//! `#[repr(C)]` mirrors of the lwIP structs the Rust modules share with the C stack,
//! from `pbuf.h`, `ip4_addr.h`, `ip6_addr.h`, `ip_addr.h`, and `netif.h`.
//!
//! Each mirror follows the C definition field for field, under the same options. When the
//! crate is built for a firmware (`lwip_layout`), every mirrored offset and size is
//! checked against the C compiler's, from `../cmake/lwip_rust_config.c`.

use core::ffi::{c_char, c_void};
use core::ptr::NonNull;

use crate::config;

/// Main packet buffer struct (`struct pbuf`).
#[repr(C)]
pub struct Pbuf {
    /// Next pbuf in singly linked pbuf chain.
    pub next: Option<NonNull<Pbuf>>,
    /// Pointer to the actual data in the buffer.
    pub payload: *mut c_void,
    /// Total length of this buffer and all next buffers in chain belonging to the same
    /// packet.
    ///
    /// For non-queue packet chains this is the invariant:
    /// `p->tot_len == p->len + (p->next? p->next->tot_len: 0)`
    pub tot_len: u16,
    /// Length of this buffer.
    pub len: u16,
    /// A bit field indicating pbuf type and allocation sources (see `PBUF_TYPE_FLAG_*`,
    /// `PBUF_ALLOC_FLAG_*` and `PBUF_TYPE_ALLOC_SRC_MASK`).
    pub type_internal: u8,
    /// Misc flags.
    pub flags: u8,
    /// The reference count always equals the number of pointers that refer to this
    /// pbuf. This can be pointers from an application, the stack itself, or `pbuf->next`
    /// pointers from a chain. (`LWIP_PBUF_REF_T`, `u8_t` by default.)
    pub ref_: u8,
    /// For incoming packets, this contains the input netif's index.
    pub if_idx: u8,
}

impl Pbuf {
    /// The `len` bytes of this pbuf's payload.
    ///
    /// # Safety
    ///
    /// `payload` is readable for `len` bytes, and not written while the slice lives.
    pub unsafe fn payload_bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `payload` is readable for `len` bytes, per the caller.
        unsafe { core::slice::from_raw_parts(self.payload.cast::<u8>(), usize::from(self.len)) }
    }
}

/// `err_t`: an lwIP error code (`s8_t`).
pub type ErrT = i8;
/// No error, everything OK.
pub const ERR_OK: ErrT = 0;
/// Out of memory error.
pub const ERR_MEM: ErrT = -1;
/// Illegal value.
pub const ERR_VAL: ErrT = -6;
/// Illegal argument.
pub const ERR_ARG: ErrT = -16;

/// `pbuf_layer`: the header room a pbuf is allocated with, in bytes (a C enum).
pub type PbufLayer = core::ffi::c_uint;
/// `PBUF_RAW`: no header room.
pub const PBUF_RAW: PbufLayer = 0;

/// `pbuf_type`: how a pbuf and its payload are allocated (a C enum).
pub type PbufType = core::ffi::c_uint;
/// Indicates that the payload directly follows the struct pbuf.
pub const PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS: u8 = 0x80;
/// Indicates the data stored in this pbuf can change.
pub const PBUF_TYPE_FLAG_DATA_VOLATILE: u8 = 0x40;
/// 4 bits are reserved for 16 allocation sources: 0=heap, 1=MEMP_PBUF,
/// 2=MEMP_PBUF_POOL.
pub const PBUF_TYPE_ALLOC_SRC_MASK: u8 = 0x0F;
/// Indicates this pbuf is used for RX.
pub const PBUF_ALLOC_FLAG_RX: PbufType = 0x0100;
/// Indicates the application needs the pbuf payload to be in one piece.
pub const PBUF_ALLOC_FLAG_DATA_CONTIGUOUS: PbufType = 0x0200;
/// Allocated from the heap.
pub const PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP: u8 = 0x00;
/// Allocated from `MEMP_PBUF`.
pub const PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF: u8 = 0x01;
/// Allocated from `MEMP_PBUF_POOL`.
pub const PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL: u8 = 0x02;
/// pbuf data is stored in RAM, used for TX mostly; struct pbuf and its payload are
/// allocated in one piece of contiguous memory.
pub const PBUF_RAM: PbufType = PBUF_ALLOC_FLAG_DATA_CONTIGUOUS
    | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS as PbufType
    | PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP as PbufType;
/// pbuf data is stored in ROM, i.e. struct pbuf and its payload are located in totally
/// different memory areas.
pub const PBUF_ROM: PbufType = PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF as PbufType;
/// pbuf comes from the pbuf pool. Much like PBUF_ROM but payload might change.
pub const PBUF_REF: PbufType =
    (PBUF_TYPE_FLAG_DATA_VOLATILE | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF) as PbufType;
/// pbuf payload refers to RAM. This one comes from a pool and should be used for RX.
pub const PBUF_POOL: PbufType = PBUF_ALLOC_FLAG_RX
    | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS as PbufType
    | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL as PbufType;

/// Indicates this is a custom pbuf: `pbuf_free` calls `pbuf_custom->custom_free_function()`
/// when the last reference is released (plus custom PBUF_RAM cannot be trimmed).
pub const PBUF_FLAG_IS_CUSTOM: u8 = 0x02;
/// Indicates this pbuf includes a TCP FIN flag.
pub const PBUF_FLAG_TCP_FIN: u8 = 0x20;

/// `NETIF_NO_INDEX`: no netif.
pub const NETIF_NO_INDEX: u8 = 0;

/// Function prototype for a function to free a custom pbuf.
pub type PbufFreeCustomFn = Option<unsafe extern "C" fn(p: *mut Pbuf)>;

/// A custom pbuf (`struct pbuf_custom`): like a pbuf, but following a function pointer to
/// free it.
#[repr(C)]
pub struct PbufCustom {
    /// The actual pbuf.
    pub pbuf: Pbuf,
    /// This function is called when `pbuf_free` deallocates this pbuf(_custom).
    pub custom_free_function: PbufFreeCustomFn,
}

/// The pbufs of the chain that starts at `p`, following `next`.
///
/// # Safety
///
/// `p` is null or the first pbuf of a well-formed chain, whose pbufs outlive `'a` and are
/// not written while it is walked.
pub unsafe fn pbuf_chain<'a>(p: *const Pbuf) -> impl Iterator<Item = &'a Pbuf> {
    // SAFETY: `p` is null or a valid pbuf, per the caller.
    let first = unsafe { p.as_ref() };
    // SAFETY: every `next` of a well-formed chain is null or a valid pbuf.
    core::iter::successors(first, |q| q.next.map(|next| unsafe { next.as_ref() }))
}

/// An IPv4 address, in network byte order (`ip4_addr_t`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ip4Addr {
    /// The address, in network byte order.
    pub addr: u32,
}

/// An IPv6 address, in network byte order (`ip6_addr_t`).
#[cfg(lwip_ipv6)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ip6Addr {
    /// The address, as four words in network byte order.
    pub addr: [u32; 4],
    /// The zone of a scoped address (`LWIP_IPV6_SCOPES`).
    #[cfg(lwip_ipv6_scopes)]
    pub zone: u8,
}

/// `IPADDR_TYPE_V4`: an IPv4 address.
pub const IPADDR_TYPE_V4: u8 = 0;
/// `IPADDR_TYPE_V6`: an IPv6 address.
pub const IPADDR_TYPE_V6: u8 = 6;
/// `IPADDR_TYPE_ANY`: an IPv4+IPv6 ("dual-stack") address.
pub const IPADDR_TYPE_ANY: u8 = 46;

/// `IPADDR_ANY`: 0.0.0.0.
pub const IPADDR_ANY: u32 = 0x0000_0000;
/// `IPADDR_BROADCAST`: 255.255.255.255.
pub const IPADDR_BROADCAST: u32 = 0xffff_ffff;
/// `IPADDR_NONE`: 255.255.255.255, as `ipaddr_addr()`'s error value.
pub const IPADDR_NONE: u32 = 0xffff_ffff;

/// The address union of a dual-stack [`IpAddr`].
#[cfg(all(lwip_ipv4, lwip_ipv6))]
#[repr(C)]
#[derive(Clone, Copy)]
pub union IpAddrUnion {
    /// The address as IPv6.
    pub ip6: Ip6Addr,
    /// The address as IPv4.
    pub ip4: Ip4Addr,
}

/// A unified IP address, IPv4 or IPv6 (`ip_addr_t`), when both are enabled.
#[cfg(all(lwip_ipv4, lwip_ipv6))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpAddr {
    /// The address.
    pub u_addr: IpAddrUnion,
    /// One of `IPADDR_TYPE_*`.
    pub type_: u8,
}

/// With only IPv4 enabled, `ip_addr_t` is `ip4_addr_t`.
#[cfg(all(lwip_ipv4, not(lwip_ipv6)))]
pub type IpAddr = Ip4Addr;

/// With only IPv6 enabled, `ip_addr_t` is `ip6_addr_t`.
#[cfg(all(lwip_ipv6, not(lwip_ipv4)))]
pub type IpAddr = Ip6Addr;

#[cfg(all(lwip_ipv4, lwip_ipv6))]
impl IpAddr {
    /// `IPADDR4_INIT(u32val)`: the IPv4 address `addr`, in network byte order.
    pub const fn v4(addr: u32) -> Self {
        Self {
            u_addr: IpAddrUnion {
                ip6: Ip6Addr {
                    addr: [addr, 0, 0, 0],
                    #[cfg(lwip_ipv6_scopes)]
                    zone: 0,
                },
            },
            type_: IPADDR_TYPE_V4,
        }
    }

    /// `IP_IS_V6_VAL()`: whether this is an IPv6 address.
    pub fn is_v6(&self) -> bool {
        self.type_ == IPADDR_TYPE_V6
    }

    /// `ip_2_ip4()`: the address as IPv4, whatever its type.
    pub fn ip4(&self) -> &Ip4Addr {
        // SAFETY: both union fields are plain integers, valid for any bits, and the
        // union is at least as large as either.
        unsafe { &self.u_addr.ip4 }
    }

    /// `ip_2_ip6()`: the address as IPv6, whatever its type.
    pub fn ip6(&self) -> &Ip6Addr {
        // SAFETY: as in `ip4`.
        unsafe { &self.u_addr.ip6 }
    }
}

#[cfg(all(lwip_ipv4, not(lwip_ipv6)))]
impl Ip4Addr {
    /// `IPADDR4_INIT(u32val)`.
    pub const fn v4(addr: u32) -> Self {
        Self { addr }
    }

    /// `ip_2_ip4()`.
    pub fn ip4(&self) -> &Ip4Addr {
        self
    }
}

/// A callback in a mirrored struct whose type no ported module uses yet: only its size
/// and alignment matter.
pub type OpaqueFn = Option<unsafe extern "C" fn()>;

/// `NETIF_FLAG_BROADCAST`: the netif has broadcast capability.
pub const NETIF_FLAG_BROADCAST: u8 = 0x02;

/// Generic data structure used for all lwIP network interfaces (`struct netif`), up to
/// and including `num`. The fields after it are not mirrored yet: a `Netif` is only ever
/// reached through a pointer to the C struct, never made or moved by value in firmware.
#[repr(C)]
pub struct Netif {
    /// Pointer to next in linked list.
    #[cfg(not(lwip_single_netif))]
    pub next: Option<NonNull<Netif>>,
    /// IP address configuration in network byte order.
    #[cfg(lwip_ipv4)]
    pub ip_addr: IpAddr,
    /// The netmask, in network byte order.
    #[cfg(lwip_ipv4)]
    pub netmask: IpAddr,
    /// The gateway, in network byte order.
    #[cfg(lwip_ipv4)]
    pub gw: IpAddr,
    /// Array of IPv6 addresses for this netif.
    #[cfg(lwip_ipv6)]
    pub ip6_addr: [IpAddr; config::LWIP_IPV6_NUM_ADDRESSES],
    /// The state of each IPv6 address (Tentative, Preferred, etc).
    #[cfg(lwip_ipv6)]
    pub ip6_addr_state: [u8; config::LWIP_IPV6_NUM_ADDRESSES],
    /// Remaining valid lifetime of each IPv6 address, in seconds.
    #[cfg(all(lwip_ipv6, lwip_ipv6_address_lifetimes))]
    pub ip6_addr_valid_life: [u32; config::LWIP_IPV6_NUM_ADDRESSES],
    /// Remaining preferred lifetime of each IPv6 address, in seconds.
    #[cfg(all(lwip_ipv6, lwip_ipv6_address_lifetimes))]
    pub ip6_addr_pref_life: [u32; config::LWIP_IPV6_NUM_ADDRESSES],
    /// Called by the network device driver to pass a packet up the TCP/IP stack.
    pub input: OpaqueFn,
    /// Called by the IP module when it wants to send a packet on the interface.
    #[cfg(lwip_ipv4)]
    pub output: OpaqueFn,
    /// Called by `ethernet_output()` when it wants to send a packet on the interface.
    pub linkoutput: OpaqueFn,
    /// Called by the IPv6 module when it wants to send a packet on the interface.
    #[cfg(lwip_ipv6)]
    pub output_ip6: OpaqueFn,
    /// Called when the netif state is set to up or down.
    #[cfg(lwip_netif_status_callback)]
    pub status_callback: OpaqueFn,
    /// Called when the netif link is set to up or down.
    #[cfg(lwip_netif_link_callback)]
    pub link_callback: OpaqueFn,
    /// Called when the netif has been removed.
    #[cfg(lwip_netif_remove_callback)]
    pub remove_callback: OpaqueFn,
    /// Set by the device driver; could point to state information for the device.
    pub state: *mut c_void,
    /// Client data slots (`netif_get_client_data`).
    pub client_data: [*mut c_void; config::LWIP_NETIF_CLIENT_DATA],
    /// The hostname for this netif; NULL is a valid value.
    #[cfg(lwip_netif_hostname)]
    pub hostname: *const c_char,
    /// Checksum generation and checking flags.
    #[cfg(lwip_checksum_ctrl_per_netif)]
    pub chksum_flags: u16,
    /// Maximum transfer unit (in bytes).
    pub mtu: u16,
    /// Maximum transfer unit (in bytes), updated by RA.
    #[cfg(all(lwip_ipv6, lwip_nd6_allow_ra_updates))]
    pub mtu6: u16,
    /// Link level hardware address of this interface.
    pub hwaddr: [u8; config::NETIF_MAX_HWADDR_LEN],
    /// Number of bytes used in hwaddr.
    pub hwaddr_len: u8,
    /// Flags (see `NETIF_FLAG_*`).
    pub flags: u8,
    /// Descriptive abbreviation.
    pub name: [c_char; 2],
    /// Number of this interface. Used for `if_api` and `netifapi_netif`, as well as for
    /// IPv6 zones.
    pub num: u8,
}

impl Netif {
    /// `netif_ip4_addr()`.
    #[cfg(lwip_ipv4)]
    pub fn ip4_addr(&self) -> &Ip4Addr {
        self.ip_addr.ip4()
    }

    /// `netif_ip4_netmask()`.
    #[cfg(lwip_ipv4)]
    pub fn ip4_netmask(&self) -> &Ip4Addr {
        self.netmask.ip4()
    }
}

#[cfg(lwip_layout)]
mod layout {
    use core::mem::{align_of, offset_of, size_of};

    use super::*;
    use crate::config::*;

    fp::static_assert!(size_of::<*const u8>() == SIZEOF_POINTER);

    fp::static_assert!(size_of::<Pbuf>() == SIZEOF_PBUF);
    fp::static_assert!(align_of::<Pbuf>() == ALIGNOF_PBUF);
    fp::static_assert!(size_of::<u8>() == SIZEOF_PBUF_REF);
    fp::static_assert!(offset_of!(Pbuf, next) == PBUF_NEXT);
    fp::static_assert!(offset_of!(Pbuf, payload) == PBUF_PAYLOAD);
    fp::static_assert!(offset_of!(Pbuf, tot_len) == PBUF_TOT_LEN);
    fp::static_assert!(offset_of!(Pbuf, len) == PBUF_LEN);
    fp::static_assert!(offset_of!(Pbuf, type_internal) == PBUF_TYPE_INTERNAL);
    fp::static_assert!(offset_of!(Pbuf, flags) == PBUF_FLAGS);
    fp::static_assert!(offset_of!(Pbuf, ref_) == PBUF_REF_COUNT);
    fp::static_assert!(offset_of!(Pbuf, if_idx) == PBUF_IF_IDX);

    #[cfg(lwip_support_custom_pbuf)]
    fp::static_assert!(size_of::<PbufCustom>() == SIZEOF_PBUF_CUSTOM);
    #[cfg(lwip_support_custom_pbuf)]
    fp::static_assert!(offset_of!(PbufCustom, custom_free_function) == PBUF_CUSTOM_FREE_FUNCTION);

    fp::static_assert!(size_of::<Ip4Addr>() == SIZEOF_IP4_ADDR);
    #[cfg(lwip_ipv6)]
    fp::static_assert!(size_of::<Ip6Addr>() == SIZEOF_IP6_ADDR);
    fp::static_assert!(size_of::<IpAddr>() == SIZEOF_IP_ADDR);
    fp::static_assert!(align_of::<IpAddr>() == ALIGNOF_IP_ADDR);
    #[cfg(all(lwip_ipv4, lwip_ipv6))]
    fp::static_assert!(offset_of!(IpAddr, type_) == IP_ADDR_TYPE);

    #[cfg(not(lwip_single_netif))]
    fp::static_assert!(offset_of!(Netif, next) == NETIF_NEXT);
    #[cfg(lwip_ipv4)]
    fp::static_assert!(offset_of!(Netif, ip_addr) == NETIF_IP_ADDR);
    #[cfg(lwip_ipv4)]
    fp::static_assert!(offset_of!(Netif, netmask) == NETIF_NETMASK);
    #[cfg(lwip_ipv4)]
    fp::static_assert!(offset_of!(Netif, gw) == NETIF_GW);
    fp::static_assert!(offset_of!(Netif, state) == NETIF_STATE);
    fp::static_assert!(offset_of!(Netif, mtu) == NETIF_MTU);
    fp::static_assert!(offset_of!(Netif, hwaddr) == NETIF_HWADDR);
    fp::static_assert!(offset_of!(Netif, flags) == NETIF_FLAGS);
    fp::static_assert!(offset_of!(Netif, num) == NETIF_NUM);
}
