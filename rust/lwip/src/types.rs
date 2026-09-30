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
/// Indicates this pbuf was received as link-level broadcast.
pub const PBUF_FLAG_LLBCAST: u8 = 0x08;
/// Indicates this pbuf was received as link-level multicast.
pub const PBUF_FLAG_LLMCAST: u8 = 0x10;
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

    /// `ip_2_ip4()`, mutable.
    pub fn ip4_mut(&mut self) -> &mut Ip4Addr {
        // SAFETY: as in `ip4`.
        unsafe { &mut self.u_addr.ip4 }
    }

    /// `ip_2_ip6()`, mutable.
    pub fn ip6_mut(&mut self) -> &mut Ip6Addr {
        // SAFETY: as in `ip4`.
        unsafe { &mut self.u_addr.ip6 }
    }

    /// `ip_addr_set_zero_ip4()`: every word and the zone zeroed, typed IPv4.
    pub fn set_zero_ip4(&mut self) {
        *self.ip6_mut() = Ip6Addr::default();
        self.type_ = IPADDR_TYPE_V4;
    }

    /// `ip_addr_set_zero_ip6()`: every word and the zone zeroed, typed IPv6.
    pub fn set_zero_ip6(&mut self) {
        *self.ip6_mut() = Ip6Addr::default();
        self.type_ = IPADDR_TYPE_V6;
    }

    /// `ip_addr_copy(dest, src)`: the type and the address; an IPv4 copy clears the other
    /// IPv6 words and the zone (`ip_clear_no4`).
    pub fn copy_from(&mut self, src: &IpAddr) {
        self.type_ = src.type_;
        if src.is_v6() {
            *self.ip6_mut() = *src.ip6();
        } else {
            self.ip4_mut().addr = src.ip4().addr;
            let ip6 = self.ip6_mut();
            ip6.addr[1] = 0;
            ip6.addr[2] = 0;
            ip6.addr[3] = 0;
            #[cfg(lwip_ipv6_scopes)]
            {
                ip6.zone = 0;
            }
        }
    }

    /// `ip_addr_copy_from_ip6(dest, src)`: `src`, typed IPv6.
    pub fn copy_from_ip6(&mut self, src: &Ip6Addr) {
        *self.ip6_mut() = *src;
        self.type_ = IPADDR_TYPE_V6;
    }
}

/// An address the stack never writes, where C passes `IP4_ADDR_ANY4`.
#[cfg(all(lwip_ipv4, lwip_ipv6))]
pub static IP4_ADDR_ANY4: Ip4Addr = Ip4Addr { addr: IPADDR_ANY };

#[cfg(lwip_ipv6)]
impl Ip6Addr {
    /// `ip6_addr_islinklocal()`: fe80::/10.
    pub fn is_link_local(&self) -> bool {
        self.addr[0] & 0xffc0_0000_u32.to_be() == 0xfe80_0000_u32.to_be()
    }

    /// `ip6_addr_zoneless_eq()`: the same address, zones aside.
    pub fn zoneless_eq(&self, other: &Ip6Addr) -> bool {
        self.addr == other.addr
    }
}

/// `IP6_ADDR_INVALID`.
pub const IP6_ADDR_INVALID: u8 = 0x00;
/// `IP6_ADDR_TENTATIVE`.
pub const IP6_ADDR_TENTATIVE: u8 = 0x08;
/// `IP6_ADDR_VALID`: this bit marks an address as valid (preferred or deprecated).
pub const IP6_ADDR_VALID: u8 = 0x10;
/// `IP6_ADDR_TENTATIVE_COUNT_MASK`: 1-7 probes sent.
pub const IP6_ADDR_TENTATIVE_COUNT_MASK: u8 = 0x07;

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

/// `ERR_BUF`: buffer error.
pub const ERR_BUF: ErrT = -2;
/// `ERR_RTE`: routing problem.
pub const ERR_RTE: ErrT = -4;
/// `ERR_IF`: low-level netif error.
pub const ERR_IF: ErrT = -12;

/// `netif_init_fn`: called by `netif_add()` to initialize a netif.
pub type NetifInitFn = Option<unsafe extern "C" fn(netif: *mut Netif) -> ErrT>;
/// `netif_input_fn`: passes a packet up the TCP/IP stack.
pub type NetifInputFn = Option<unsafe extern "C" fn(p: *mut Pbuf, inp: *mut Netif) -> ErrT>;
/// `netif_output_fn`: sends an IPv4 packet on the interface.
#[cfg(lwip_ipv4)]
pub type NetifOutputFn =
    Option<unsafe extern "C" fn(netif: *mut Netif, p: *mut Pbuf, ipaddr: *const Ip4Addr) -> ErrT>;
/// `netif_output_ip6_fn`: sends an IPv6 packet on the interface.
#[cfg(lwip_ipv6)]
pub type NetifOutputIp6Fn =
    Option<unsafe extern "C" fn(netif: *mut Netif, p: *mut Pbuf, ipaddr: *const Ip6Addr) -> ErrT>;
/// `netif_linkoutput_fn`: sends a raw packet (Ethernet frame) on the interface.
pub type NetifLinkoutputFn = Option<unsafe extern "C" fn(netif: *mut Netif, p: *mut Pbuf) -> ErrT>;
/// `netif_status_callback_fn`: called when a netif changes status.
pub type NetifStatusCallbackFn = Option<unsafe extern "C" fn(netif: *mut Netif)>;
/// `netif_igmp_mac_filter_fn`: adds or deletes an entry in the IPv4 multicast filter.
#[cfg(lwip_ipv4)]
pub type NetifIgmpMacFilterFn = Option<
    unsafe extern "C" fn(
        netif: *mut Netif,
        group: *const Ip4Addr,
        action: core::ffi::c_uint,
    ) -> ErrT,
>;
/// `netif_mld_mac_filter_fn`: adds or deletes an entry in the IPv6 multicast filter.
#[cfg(lwip_ipv6)]
pub type NetifMldMacFilterFn = Option<
    unsafe extern "C" fn(
        netif: *mut Netif,
        group: *const Ip6Addr,
        action: core::ffi::c_uint,
    ) -> ErrT,
>;

/// Whether the netif is up (`NETIF_FLAG_UP`).
pub const NETIF_FLAG_UP: u8 = 0x01;
/// `NETIF_FLAG_BROADCAST`: the netif has broadcast capability.
pub const NETIF_FLAG_BROADCAST: u8 = 0x02;
/// If set, the interface has an active link (set by the network interface driver).
pub const NETIF_FLAG_LINK_UP: u8 = 0x04;
/// If set, the netif is an ethernet device using ARP.
pub const NETIF_FLAG_ETHARP: u8 = 0x08;
/// If set, the netif is an ethernet device. It might not use ARP or TCP/IP if it is used
/// for PPPoE only.
pub const NETIF_FLAG_ETHERNET: u8 = 0x10;
/// If set, the netif has IGMP capability.
pub const NETIF_FLAG_IGMP: u8 = 0x20;
/// If set, the netif has MLD6 capability.
pub const NETIF_FLAG_MLD6: u8 = 0x40;

/// Generic data structure used for all lwIP network interfaces (`struct netif`).
///
/// The fields follow `netif.h` under the options `build.rs` supports; the MIB2
/// statistics and `netif_hint` fields are not mirrored, which the layout checks enforce.
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
    pub input: NetifInputFn,
    /// Called by the IP module when it wants to send a packet on the interface.
    #[cfg(lwip_ipv4)]
    pub output: NetifOutputFn,
    /// Called by `ethernet_output()` when it wants to send a packet on the interface.
    pub linkoutput: NetifLinkoutputFn,
    /// Called by the IPv6 module when it wants to send a packet on the interface.
    #[cfg(lwip_ipv6)]
    pub output_ip6: NetifOutputIp6Fn,
    /// Called when the netif state is set to up or down.
    #[cfg(lwip_netif_status_callback)]
    pub status_callback: NetifStatusCallbackFn,
    /// Called when the netif link is set to up or down.
    #[cfg(lwip_netif_link_callback)]
    pub link_callback: NetifStatusCallbackFn,
    /// Called when the netif has been removed.
    #[cfg(lwip_netif_remove_callback)]
    pub remove_callback: NetifStatusCallbackFn,
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
    /// Is this netif enabled for IPv6 autoconfiguration.
    #[cfg(all(lwip_ipv6, lwip_ipv6_autoconfig))]
    pub ip6_autoconfig_enabled: u8,
    /// Number of Router Solicitation messages that remain to be sent.
    #[cfg(all(lwip_ipv6, lwip_ipv6_send_router_solicit))]
    pub rs_count: u8,
    /// Called to add or delete an entry in the multicast filter table of the ethernet
    /// MAC.
    #[cfg(all(lwip_ipv4, lwip_igmp))]
    pub igmp_mac_filter: NetifIgmpMacFilterFn,
    /// Called to add or delete an entry in the IPv6 multicast filter table of the
    /// ethernet MAC.
    #[cfg(all(lwip_ipv6, lwip_ipv6_mld))]
    pub mld_mac_filter: NetifMldMacFilterFn,
    /// Address conflict detection state (`struct acd *`).
    #[cfg(lwip_acd)]
    pub acd_list: *mut c_void,
    /// List of packets to be queued for ourselves.
    #[cfg(enable_loopback)]
    pub loop_first: Option<NonNull<Pbuf>>,
    /// The last packet queued for ourselves.
    #[cfg(enable_loopback)]
    pub loop_last: Option<NonNull<Pbuf>>,
    /// The pbufs queued for ourselves.
    #[cfg(all(enable_loopback, lwip_loopback_max_pbufs))]
    pub loop_cnt_current: u16,
    /// Used if the original scheduling failed.
    #[cfg(all(enable_loopback, lwip_netif_loopback_multithreading))]
    pub reschedule_poll: u8,
    /// NAPT enabled on this interface.
    #[cfg(all(lwip_ipv4, ip_napt))]
    pub napt: u8,
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

    /// `netif_ip4_gw()`.
    #[cfg(lwip_ipv4)]
    pub fn ip4_gw(&self) -> &Ip4Addr {
        self.gw.ip4()
    }

    /// `netif_get_index()`: the netif's index, its number plus one.
    pub fn index(&self) -> u8 {
        self.num.wrapping_add(1)
    }
}

/// `netif_nsc_reason_t`: why an extended status callback is called (`LWIP_NSC_*`).
pub type NetifNscReason = u16;

/// `netif_ext_callback_args_t`: the arguments of an extended status callback, by reason.
#[repr(C)]
#[derive(Clone, Copy)]
pub union NetifExtCallbackArgs {
    /// `LWIP_NSC_LINK_CHANGED`: 1 when up, 0 when down.
    pub link_changed: StateChanged,
    /// `LWIP_NSC_STATUS_CHANGED`: 1 when up, 0 when down.
    pub status_changed: StateChanged,
    /// The IPv4 changes.
    pub ipv4_changed: Ipv4Changed,
    /// `LWIP_NSC_IPV6_SET`.
    pub ipv6_set: Ipv6Set,
    /// `LWIP_NSC_IPV6_ADDR_STATE_CHANGED`.
    pub ipv6_addr_state_changed: Ipv6AddrStateChanged,
}

/// `link_changed_s` and `status_changed_s`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StateChanged {
    /// 1: up; 0: down.
    pub state: u8,
}

/// `ipv4_changed_s`: the old IPv4 settings.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Changed {
    /// Old IPv4 address.
    pub old_address: *const IpAddr,
    /// Old netmask.
    pub old_netmask: *const IpAddr,
    /// Old gateway.
    pub old_gw: *const IpAddr,
}

/// `ipv6_set_s`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Set {
    /// Index of changed IPv6 address.
    pub addr_index: i8,
    /// Old IPv6 address.
    pub old_address: *const IpAddr,
}

/// `ipv6_addr_state_changed_s`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6AddrStateChanged {
    /// Index of affected IPv6 address.
    pub addr_index: i8,
    /// Old IPv6 address state.
    pub old_state: u8,
    /// Affected IPv6 address.
    pub address: *const IpAddr,
}

/// `netif_ext_callback_fn`: an extended netif status callback.
pub type NetifExtCallbackFn = Option<
    unsafe extern "C" fn(
        netif: *mut Netif,
        reason: NetifNscReason,
        args: *const NetifExtCallbackArgs,
    ),
>;

/// `netif_ext_callback_t`: a registered extended status callback.
#[repr(C)]
pub struct NetifExtCallback {
    /// The function to call.
    pub callback_fn: NetifExtCallbackFn,
    /// The next registered callback.
    pub next: *mut NetifExtCallback,
}

/// The length of an Ethernet address (`ETH_HWADDR_LEN`).
pub const ETH_HWADDR_LEN: usize = 6;

/// An Ethernet MAC address (`struct eth_addr`, packed).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EthAddr {
    /// The address bytes.
    pub addr: [u8; ETH_HWADDR_LEN],
}

/// Ethernet header (`struct eth_hdr`, packed; `ETH_PAD_SIZE` 0).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    /// Destination address.
    pub dest: EthAddr,
    /// Source address.
    pub src: EthAddr,
    /// Ethertype, in network byte order.
    pub type_: u16,
}

/// `SIZEOF_ETH_HDR`.
pub const SIZEOF_ETH_HDR: u16 = core::mem::size_of::<EthHdr>() as u16;

/// `ETHTYPE_IP`: Internet protocol v4.
pub const ETHTYPE_IP: u16 = 0x0800;
/// `ETHTYPE_ARP`: Address resolution protocol.
pub const ETHTYPE_ARP: u16 = 0x0806;
/// `ETHTYPE_IPV6`: Internet protocol v6.
pub const ETHTYPE_IPV6: u16 = 0x86DD;

/// An IPv4 address that may be only 16-bit aligned (`struct ip4_addr2`, packed): as it is
/// in an ARP header.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ip4Addr2 {
    /// The address as two 16-bit halves, in memory order.
    pub addrw: [u16; 2],
}

/// The ARP message, see RFC 826 ("Packet format") (`struct etharp_hdr`, packed).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EtharpHdr {
    /// Hardware type.
    pub hwtype: u16,
    /// Protocol type.
    pub proto: u16,
    /// Hardware address length.
    pub hwlen: u8,
    /// Protocol address length.
    pub protolen: u8,
    /// Operation.
    pub opcode: u16,
    /// Sender hardware address.
    pub shwaddr: EthAddr,
    /// Sender protocol address.
    pub sipaddr: Ip4Addr2,
    /// Target hardware address.
    pub dhwaddr: EthAddr,
    /// Target protocol address.
    pub dipaddr: Ip4Addr2,
}

/// `SIZEOF_ETHARP_HDR`.
pub const SIZEOF_ETHARP_HDR: u16 = core::mem::size_of::<EtharpHdr>() as u16;

/// `struct etharp_q_entry`: a packet queued on an ARP entry.
#[repr(C)]
pub struct EtharpQEntry {
    /// The next queued packet.
    pub next: *mut EtharpQEntry,
    /// The packet.
    pub p: *mut Pbuf,
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
    fp::static_assert!(size_of::<Netif>() == SIZEOF_NETIF);
    fp::static_assert!(align_of::<Netif>() == ALIGNOF_NETIF);
    fp::static_assert!(offset_of!(Netif, input) == NETIF_INPUT);
    fp::static_assert!(offset_of!(Netif, linkoutput) == NETIF_LINKOUTPUT);
    fp::static_assert!(offset_of!(Netif, client_data) == NETIF_CLIENT_DATA);
    #[cfg(lwip_ipv6)]
    fp::static_assert!(offset_of!(Netif, ip6_addr) == NETIF_IP6_ADDR);
    #[cfg(lwip_ipv6)]
    fp::static_assert!(offset_of!(Netif, ip6_addr_state) == NETIF_IP6_ADDR_STATE);
    #[cfg(lwip_ipv6)]
    fp::static_assert!(offset_of!(Netif, output_ip6) == NETIF_OUTPUT_IP6);
    #[cfg(all(lwip_ipv6, lwip_ipv6_autoconfig))]
    fp::static_assert!(offset_of!(Netif, ip6_autoconfig_enabled) == NETIF_IP6_AUTOCONFIG_ENABLED);
    #[cfg(all(lwip_ipv6, lwip_ipv6_mld))]
    fp::static_assert!(offset_of!(Netif, mld_mac_filter) == NETIF_MLD_MAC_FILTER);
    #[cfg(all(lwip_ipv4, lwip_igmp))]
    fp::static_assert!(offset_of!(Netif, igmp_mac_filter) == NETIF_IGMP_MAC_FILTER);
    #[cfg(lwip_acd)]
    fp::static_assert!(offset_of!(Netif, acd_list) == NETIF_ACD_LIST);
    #[cfg(enable_loopback)]
    fp::static_assert!(offset_of!(Netif, loop_first) == NETIF_LOOP_FIRST);
    #[cfg(enable_loopback)]
    fp::static_assert!(offset_of!(Netif, loop_last) == NETIF_LOOP_LAST);
    #[cfg(all(enable_loopback, lwip_loopback_max_pbufs))]
    fp::static_assert!(offset_of!(Netif, loop_cnt_current) == NETIF_LOOP_CNT_CURRENT);
    #[cfg(all(enable_loopback, lwip_netif_loopback_multithreading))]
    fp::static_assert!(offset_of!(Netif, reschedule_poll) == NETIF_RESCHEDULE_POLL);
    #[cfg(all(lwip_ipv4, ip_napt))]
    fp::static_assert!(offset_of!(Netif, napt) == NETIF_NAPT);

    #[cfg(lwip_netif_ext_status_callback)]
    fp::static_assert!(size_of::<NetifExtCallback>() == SIZEOF_NETIF_EXT_CALLBACK);
    #[cfg(lwip_netif_ext_status_callback)]
    fp::static_assert!(offset_of!(NetifExtCallback, next) == NETIF_EXT_CALLBACK_NEXT);
    #[cfg(lwip_netif_ext_status_callback)]
    fp::static_assert!(size_of::<NetifExtCallbackArgs>() == SIZEOF_NETIF_EXT_CALLBACK_ARGS);
    #[cfg(lwip_netif_ext_status_callback)]
    fp::static_assert!(size_of::<NetifNscReason>() == SIZEOF_NETIF_NSC_REASON);

    #[cfg(all(lwip_arp, arp_queueing))]
    fp::static_assert!(size_of::<EtharpQEntry>() == SIZEOF_ETHARP_Q_ENTRY);
    #[cfg(all(lwip_arp, arp_queueing))]
    fp::static_assert!(offset_of!(EtharpQEntry, p) == ETHARP_Q_ENTRY_P);
    fp::static_assert!(size_of::<EthAddr>() == SIZEOF_ETH_ADDR);
    fp::static_assert!(size_of::<EthHdr>() == SIZEOF_STRUCT_ETH_HDR);
    fp::static_assert!(offset_of!(EthHdr, type_) == ETH_HDR_TYPE);
    fp::static_assert!(size_of::<EtharpHdr>() == SIZEOF_STRUCT_ETHARP_HDR);
    fp::static_assert!(offset_of!(EtharpHdr, opcode) == ETHARP_HDR_OPCODE);
    fp::static_assert!(offset_of!(EtharpHdr, sipaddr) == ETHARP_HDR_SIPADDR);
    fp::static_assert!(offset_of!(EtharpHdr, dipaddr) == ETHARP_HDR_DIPADDR);
}
