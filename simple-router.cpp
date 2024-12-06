/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  // Extract information from packet header
  if (packet.size() < sizeof(ethernet_hdr)) {
    std::cerr << "Packet too small to contain ethernet header" << std::endl;
    return;
  }
  const unsigned char* cursor = packet.data();
  auto eth_cursor = (ethernet_hdr*)cursor;
  auto ether_type = ntohs(eth_cursor->ether_type);
  // MAC addresses
  Buffer src_mac(ETHER_ADDR_LEN, 0);
  Buffer dst_mac(ETHER_ADDR_LEN, 0);
  memcpy(src_mac.data(), eth_cursor->ether_dhost, ETHER_ADDR_LEN);
  memcpy(dst_mac.data(), eth_cursor->ether_shost, ETHER_ADDR_LEN);
  // Several types of packets
  if (ether_type == ethertype_arp) { // Check if packet is ARP
    auto arp_cursor = (arp_hdr*)(cursor + sizeof(ethernet_hdr));
    auto arp_opcode = ntohs(arp_cursor->arp_op);
    if (arp_opcode == arp_op_request) {
      if (arp_cursor->arp_tip == iface->ip) {
        std::cerr << "Receive arp request from " << ipToString(arp_cursor->arp_sip) << std::endl;
        sendArpReply(arp_cursor->arp_tip, arp_cursor->arp_sip, iface->addr, src_mac, inIface);
      } else {
        std::cout << "Arp destination is not the router, ignoring." << std::endl;
        return;
      }
    } else if (arp_opcode == arp_op_reply) {
      std::cout << "Receive arp reply from " << macToString(src_mac) << std::endl;
      // Check if ARP cache has this IP address
      if (!m_arp.lookup(arp_cursor->arp_sip)) {
        auto arp_request = m_arp.insertArpEntry(dst_mac, arp_cursor->arp_sip);
        if (arp_request) {
          for (auto& pending_packet : arp_request->packets) {
            handlePacket(pending_packet.packet, pending_packet.iface);
          }
          m_arp.removeRequest(arp_request);
        } 
        else return;
      }
    }
  } else if (ether_type == ethertype_ip) { // Check if packet is IP
    auto ip_cursor = (ip_hdr*)(cursor + sizeof(ethernet_hdr));
    auto src_ip = ip_cursor->ip_src;
    auto entry = m_arp.lookup(src_ip);
    std::cout << "Receive IPv4 from " << ipToString(src_ip) << std::endl;
    std::cout << "Sending IPv4 to "   << ipToString(ip_cursor->ip_dst) << std::endl;
    // Calculate IP checksum
    if (cksum((const void*)ip_cursor, sizeof(ip_hdr)) != 0xFFFF) {
      std::cerr << "Invalid IP checksum, dropping packet" << std::endl;
      return;
    }
    if (findIfaceByIp(ip_cursor->ip_dst)) { // Check if destination IP is local
      std::cout << "IP packet destinated to the router." << std::endl;
      if (!entry) {
        m_arp.queueRequest(src_ip, packet, inIface);
        return;
        // m_arp.insertArpEntry(src_mac ,ip_cursor->ip_src);
      }
      if (ip_cursor->ip_p == ip_protocol_icmp) { // Check if packet is ICMP
        sendIcmp(packet, inIface);
      } else if(ip_cursor->ip_p == 0x0006 || ip_cursor->ip_p == 0x0011) { 
        sendIcmpType3(PendingPacket({packet, inIface}), 3, 3);
      } else {
        std::cerr << "Unsupported protocol, ignoring" << std::endl;
      }
    } else { // Desination IP is not local, forward packet
      if (ip_cursor->ip_ttl <= 1) { // Check if time out
        if (!entry) {
          m_arp.queueRequest(src_ip, packet, inIface);
          return;
          // m_arp.insertArpEntry(src_mac ,ip_cursor->ip_src);
        }
        std::cout << "Sent time exceeded message." << std::endl;
        sendIcmpType3(PendingPacket({packet, inIface}), 11, 0);
      } else {
        std::cout << "Forwarding IPv4 packet" << std::endl;
        auto forward_entry = m_routingTable.lookup(ip_cursor->ip_dst);
        auto outIface_name = forward_entry.ifName;
        auto outIface = findIfaceByName(outIface_name);
        auto arp_entry = m_arp.lookup(ip_cursor->ip_dst);
        if (!arp_entry) {
          m_arp.queueRequest(ip_cursor->ip_dst, packet, inIface);
          return;
        }
        sendIpv4(packet, outIface, arp_entry->mac);
      }
    }
  }
}

void 
SimpleRouter::sendArpRequest(const uint32_t& dst_ip)
{
  std::cout << "Sending arp request" << std::endl;
  Buffer reply_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr), 0);
  const unsigned char* cursor = reply_packet.data();
  // Get interface / IP address
  auto outIface_name = m_routingTable.lookup(dst_ip).ifName;
  auto outIface = findIfaceByName(outIface_name);
  auto outIface_addr = outIface->addr;
  auto outIface_ip   = outIface->ip;
  // Ethernet header
  auto eth_cursor = (ethernet_hdr*)cursor;
  memcpy(eth_cursor->ether_shost, outIface_addr.data(), sizeof(outIface_addr));
  memset(eth_cursor->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  eth_cursor->ether_type = htons(ethertype_arp);
  // printf("Kumitate Ether\n");
  // print_hdr_eth((uint8_t *)eth_cursor);
  // ARP header
  auto arp_cursor = (arp_hdr*)(cursor + sizeof(ethernet_hdr));
  arp_cursor->arp_hrd = htons(arp_hrd_ethernet);
  arp_cursor->arp_pro = htons(ethertype_ip);
  arp_cursor->arp_hln = (unsigned char)ETHER_ADDR_LEN;
  arp_cursor->arp_pln = (unsigned char)4;
  arp_cursor->arp_op  = htons(arp_op_request);
  arp_cursor->arp_sip = outIface_ip;
  arp_cursor->arp_tip = dst_ip;
  memcpy(arp_cursor->arp_sha, outIface_addr.data(), ETHER_ADDR_LEN);
  memset(arp_cursor->arp_tha, 0xFF, ETHER_ADDR_LEN);
  // printf("Kumitate ARP\n");
  // print_hdr_arp((uint8_t *)arp_cursor);
  // Send ARP request
  sendPacket(reply_packet, outIface_name);
}

void
SimpleRouter::sendArpReply(
  const uint32_t& src_ip, const uint32_t& dst_ip, const Buffer& src_mac, const Buffer& dst_mac, const std::string& inIface
) {
  Buffer reply_packet(sizeof(ethernet_hdr) + sizeof(arp_hdr), 0);
  const unsigned char* cursor = reply_packet.data();
  // Ethernet header
  auto eth_cursor = (ethernet_hdr*)cursor;
  memcpy(eth_cursor->ether_shost, src_mac.data(), ETHER_ADDR_LEN);
  memcpy(eth_cursor->ether_dhost, dst_mac.data(), ETHER_ADDR_LEN);
  eth_cursor->ether_type = htons(ethertype_arp);
  // ARP header
  auto arp_cursor = (arp_hdr*)(cursor + sizeof(ethernet_hdr));
  arp_cursor->arp_hrd = htons(arp_hrd_ethernet);
  arp_cursor->arp_pro = htons(ethertype_ip);
  arp_cursor->arp_hln = ETHER_ADDR_LEN;
  arp_cursor->arp_pln = (unsigned char)4;
  arp_cursor->arp_op  = htons(arp_op_reply);
  arp_cursor->arp_sip = src_ip;
  arp_cursor->arp_tip = dst_ip;
  memcpy(arp_cursor->arp_sha, src_mac.data(), ETHER_ADDR_LEN);
  memcpy(arp_cursor->arp_tha, dst_mac.data(), ETHER_ADDR_LEN);
  std::cout << "Sending to " << ipToString(dst_ip) 
            << " from interface " << inIface << std::endl;
  // Send ARP reply
  sendPacket(reply_packet, inIface);
}

void
SimpleRouter::sendIcmp(const Buffer& packet, const std::string& outIface) 
{
  std::cout << "Sending Icmp packet" << std::endl;
  // Extract information from pending packet
  Buffer icmp_packet = Buffer(packet);
  const unsigned char* cursor = icmp_packet.data();
  const unsigned char* orgcur = packet.data();
  // Ethernet header
  auto *eth_cursor = (ethernet_hdr*)cursor;
  auto *org_eth_cursor = (ethernet_hdr*)orgcur;
  memcpy(eth_cursor->ether_dhost, org_eth_cursor->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_cursor->ether_shost, org_eth_cursor->ether_dhost, ETHER_ADDR_LEN);
  eth_cursor->ether_type = htons(ethertype_ip);
  // IPv4 header
  auto *ip_cursor = (ip_hdr*)(cursor + sizeof(ethernet_hdr));
  auto *org_ip_cursor = (ip_hdr*)(orgcur + sizeof(ethernet_hdr));
  ip_cursor->ip_ttl = (uint8_t)64;
  ip_cursor->ip_src = org_ip_cursor->ip_dst;
  ip_cursor->ip_dst = org_ip_cursor->ip_src;
  ip_cursor->ip_sum = 0;
  ip_cursor->ip_sum = cksum((const void*)ip_cursor, sizeof(ip_hdr));
  // ICMP t3 header
  auto *icmp_cursor = (icmp_t3_hdr*)(cursor + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  icmp_cursor->icmp_type = (uint8_t)0;
  icmp_cursor->icmp_code = (uint8_t)0;
  icmp_cursor->icmp_sum  = 0;
  auto icmp_hdr_length = packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr);
  icmp_cursor->icmp_sum  = cksum((const void*)icmp_cursor, icmp_hdr_length);
  // Send ICMP packet
  sendPacket(icmp_packet, outIface);
}

void
SimpleRouter::sendIcmpType3(const PendingPacket& pending_packet, uint8_t type, uint8_t code)
{
  std::cout << "Sending Icmp type 3 packet" << std::endl;
  // Extract information from pending packet
  auto frame = pending_packet.packet;
  auto iface = findIfaceByName(pending_packet.iface);
  Buffer icmp_packet(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr), 0);
  // Prepare ICMP packet
  makeIcmpt3Packet(frame, iface, icmp_packet, type, code);
  sendPacket(icmp_packet, pending_packet.iface);
}

void 
SimpleRouter::makeIcmpt3Packet(
  const Buffer& frame, const Interface* iface, Buffer& icmp_packet, uint8_t type, uint8_t code
) {
  const unsigned char* cursor = icmp_packet.data();
  // MAC addresse
  auto ip_ptr  = (ip_hdr*)(frame.data() + sizeof(ethernet_hdr));
  auto src_ip  = ip_ptr->ip_src;
  // Ethernet header
  auto *eth_cursor = (ethernet_hdr*)cursor;
  auto *buf_cursor = (ethernet_hdr*)((uint8_t*)frame.data());
  memcpy(eth_cursor->ether_dhost, buf_cursor->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_cursor->ether_shost, buf_cursor->ether_dhost, ETHER_ADDR_LEN);
  eth_cursor->ether_type = htons(ethertype_ip);
  // IPv4 header
  auto *ip_cursor = (ip_hdr*)(cursor + sizeof(ethernet_hdr));
  ip_cursor->ip_v   = (uint8_t)4;
  ip_cursor->ip_hl  = (uint8_t)5;
  ip_cursor->ip_tos = (uint8_t)0;
  ip_cursor->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  ip_cursor->ip_id  = (uint16_t)rand();
  ip_cursor->ip_off = htons(IP_DF);
  ip_cursor->ip_ttl = (uint8_t)64;
  ip_cursor->ip_p   = (uint8_t)ip_protocol_icmp;
  ip_cursor->ip_src = iface->ip;
  ip_cursor->ip_dst = src_ip;
  ip_cursor->ip_sum = cksum((const void*)ip_cursor, sizeof(ip_hdr));
  // ICMP t3 header
  auto *icmp_cursor = (icmp_t3_hdr*)(cursor + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  icmp_cursor->icmp_type = type;
  icmp_cursor->icmp_code = code;
  icmp_cursor->unused    = 0;
  icmp_cursor->next_mtu  = 0;
  memcpy(icmp_cursor->data, ip_ptr, ICMP_DATA_SIZE);
  icmp_cursor->icmp_sum  = cksum((const void*)icmp_cursor, sizeof(icmp_t3_hdr));
}

void
SimpleRouter::sendIpv4(const Buffer& packet, const Interface* iface, const Buffer& dst_mac)
{
  // Extract information from pending packet
  Buffer ipv4_packet(packet);
  const unsigned char* cursor = ipv4_packet.data();
  // Ethernet header
  auto eth_cursor = (ethernet_hdr*)cursor;
  memcpy(eth_cursor->ether_shost, (iface->addr).data(), ETHER_ADDR_LEN);
  memcpy(eth_cursor->ether_dhost, dst_mac.data(), ETHER_ADDR_LEN);

  // IPv4 header
  auto ip_cursor = (ip_hdr*)(cursor + sizeof(ethernet_hdr));
  ip_cursor->ip_ttl -= 1;
  ip_cursor->ip_sum  = 0;
  ip_cursor->ip_sum  = cksum(ip_cursor, sizeof(ip_hdr));
  // Send packet
  std::cout << "Sending IPv4 to " << ipToString(ip_cursor->ip_dst) 
            <<" via " << macToString(iface->addr) << std::endl;
  sendPacket(ipv4_packet, iface->name);
  // print_hdrs(ipv4_packet);
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
