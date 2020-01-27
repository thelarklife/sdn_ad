#!/usr/bin/python

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), ""))

from optparse    import OptionParser
from prettytable import PrettyTable
from lxml import etree
from collections import defaultdict
import json
import time
import datetime
import urllib2
import re

from base import ApiCaller
from base import KeystoneCredential
from base import API_DEFAULT
from base import AUTH_API_DEFAULT

data_dir = "./"
prog_ip  = re.compile("^\d+\.\d+\.\d+\.\d+$")
prog_mac = re.compile("^\S+:\S+:\S+:\S+:\S+:\S+$")

#########################################################################
####### Write File #######

class WriteFile:
  def __init__(self, save_file, time_str):
    os.system('mkdir -p %s' %data_dir)
    self.result_file = "%s/%s_%s.log" %(data_dir, save_file, time_str)

  def open(self):
    self.RESULTp = open(self.result_file, "a+")

  def close(self):
    self.RESULTp.close()

  def write(self, line):
    self.RESULTp.write(line)
    self.RESULTp.write("\n")
    print line.strip()

  def writejson(self, response):
    self.RESULTp.write(json.dumps(response, indent=2, sort_keys=True))
    self.RESULTp.write("\n\n")

#########################################################################
####### Compute read(Compute) #######

def compute_source2nexthop(vn, x, tag_source, tag_next_hop):
  _source = x.findtext(tag_source)
  if _source in vn.compute_name_list:
    if x.findtext(tag_next_hop):
      vn.compute_name2ip[_source] = x.findtext(tag_next_hop)

#########################################################################
####### attribute bgp #######

def bgp_attribute_string(attr, x, tag):
  _attr = x.findtext(tag, default='-')
  if _attr:
    attr += _attr + "\n"
  else:
    attr += "-\n"
  return(attr)

#########################################################################
####### attribute bgp list ########

def bgp_attribute_list(attr, x, tag):
  _attrs = ""
  for _attr in x.xpath(tag):
    _attrs += _attr.text + "|"
  _attrs = re.sub('\|$', '', _attrs)
  if _attrs:
    attr += _attrs + "\n"
  else:
    attr += "-\n"
  return(attr)

#########################################################################
####### attribute evpn ########

def evpn_prefix_parse(evpn_prefix):
  _l2 = "-"
  _l3 = "-"
  l2l3s = evpn_prefix.split('-')
  l2l3s = l2l3s[-1]
  l2l3s = l2l3s.split(',')
  for l2l3 in l2l3s:
    if prog_ip.match(l2l3):
      _l3 = l2l3
    elif prog_mac.match(l2l3):
      _l2 = l2l3
  return(_l2.strip(), _l3.strip())

#########################################################################
####### attribute parse ########

def info_prefix_parse(info_prefix):
  _l2 = "-"
  _l3 = "-"
  _adv = "-"
  l2l3s = info_prefix.split('-')
  _l2_temp = l2l3s[1]
  if prog_mac.match(_l2_temp):
    _l2 = _l2_temp
  _l3_temps = l2l3s[-1].split(" ")
  if prog_ip.match(_l3_temps[0]):
      _l3 = _l3_temps[0]
  if len(_l3_temps) > 1:
    if prog_ip.match(_l3_temps[1]):
        _adv = _l3_temps[1]
  return(_l2.strip(), _l3.strip(), _adv.strip())

#########################################################################

#########################################################################


def get_l2_ctrl(vn):
  if options.brief_flag:
    header = [
                 'l2',
                 'l3',
                 'controller',
                 'prot',
                 'lp',
                 'source',
                 'nexthop',
                 'label',
                 'seq',
          ]
  else:
    header = [
                 'l2',
                 'l3',
                 'controller',
                 'prot',
                 'last_modified',
                 'lp',
                 #'med',
                 'las',
                 'pas',
                 'peer_router_id',
                 'source',
                 'nexthop',
                 'label',
                 #'replicated',
                 #'secondary_tables',
                 #'communities',
                 #'origin_vn',
                 #'flags',
                 'seq',
                 #'tunnel_encap'
          ]

  table = PrettyTable(header)
  prefix_count = defaultdict(list)
  all_prefix   = defaultdict(dict)
  for controller in CONTROLLERS:
    prefix_count[controller] = 0
    url = "http://%s:8083/%s" %(controller, vn.sandesh_rt_url)
    while url:
      error_flag = False
      print "In progress GET %s" %url
      try:
        response = urllib2.urlopen(url)
        data = unicode(response.read(), 'utf-8')
        response.close()
      except KeyboardInterrupt:
        wfr.close()
        sys.exit()
      except:
        print "Controller Route Get error"
        error_flag = True

      if ((response != None) & (error_flag == False)):
        root = etree.XML(data)
        all_prefix = parse_l2_ctrl(vn, controller, root, all_prefix, prefix_count)

      nextpage = root.xpath('//next_batch')[0].text
      if nextpage:
        nextpage  = urllib2.quote(nextpage.encode("utf-8"))
        url = "http://%s:8083/Snh_ShowRouteReqIterate?x=%s" %(controller, nextpage)
      else:
        url = ""


  for key, value in sorted(all_prefix.items()):
    (
        evpn_prefix,
         _l2,
         _l3,
         controller
    )                           = key
    (
        _protocol,
        _last_modified,
        _local_preference,
        _med,
        _local_as,
        _peer_as,
        _peer_router_id,
        _next_hop,
        _source,
        _label,
        _replicated,
        _secondary_tables,
        _communities,
        _origin_vn,
        _flags,
        _sequence_no,
        _tunnel_encap
    )                           = value

    if options.brief_flag:
      table.add_row([
                   _l2,
                   _l3,
                   controller,
                   _protocol,
                   _local_preference,
                   _next_hop,
                   _source,
                   _label,
                   _sequence_no,
                ])

    else:
      table.add_row([
                   _l2,
                   _l3,
                   controller,
                   _protocol,
                   _last_modified,
                   _local_preference,
                   _local_as,
                   _peer_as,
                   _peer_router_id,
                   _next_hop,
                   _source,
                   _label,
                   _sequence_no,
                   #_tunnel_encap
                ])


  sys.stdout = open(wfr.result_file,"a+")
  print "\n"
  print "########## Controllers Sandesh ##########\n"
  print datetime.datetime.today()
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print table
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print "\n"
  sys.stdout.close()
  sys.stdout = sys.__stdout__

  print "\n"
  print "########## Controllers Sandesh ##########\n"
  print datetime.datetime.today()
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print table
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print "\n"


#########################################################################
def parse_l2_ctrl(vn, controller, root, all_prefix, prefix_count):
      prefixes = root.xpath('//prefix')
      for prefix in prefixes:
        prefix_count[controller] += 1
        _l2   = ""
        _l3   = ""
        _protocol = ""
        _last_modified = ""
        _local_preference = ""
        _med = ""
        _local_as = ""
        _peer_as = ""
        _peer_router_id = ""
        _source = ""
        _next_hop = ""
        _label = ""
        _replicated = ""
        _secondary_tables = ""
        _communities = ""
        _origin_vn = ""
        _flags = ""
        _sequence_no = ""
        _tunnel_encap = ""

        evpn_prefix = prefix.text
        (_l2, _l3) = evpn_prefix_parse(evpn_prefix)
        for paths in prefix.itersiblings(tag = 'paths'): #preceding=False
          _showroutepaths = paths.xpath('./list/ShowRoutePath')
          for _showroutepath in _showroutepaths:
            _protocol          = bgp_attribute_string(_protocol,         _showroutepath, './protocol')
            _last_modified     = bgp_attribute_string(_last_modified,    _showroutepath, './last_modified')
            _local_preference  = bgp_attribute_string(_local_preference, _showroutepath, './local_preference')
            _med               = bgp_attribute_string(_med,              _showroutepath, './med')
            _local_as          = bgp_attribute_string(_local_as,         _showroutepath, './local_as')
            _peer_as           = bgp_attribute_string(_peer_as,          _showroutepath, './peer_as')
            _peer_router_id    = bgp_attribute_string(_peer_router_id,   _showroutepath, './peer_router_id')
            _source            = bgp_attribute_string(_source,           _showroutepath, './source')
            _next_hop          = bgp_attribute_string(_next_hop,         _showroutepath, './next_hop')
            _label             = bgp_attribute_string(_label,            _showroutepath, './label')
            _replicated        = bgp_attribute_string(_replicated,       _showroutepath, './replicated')
            _secondary_tables  = bgp_attribute_list(_secondary_tables,   _showroutepath, './secondary_tables/list/element')
            _communities       = bgp_attribute_list(_communities,        _showroutepath, './communities/list/element')
            _origin_vn         = bgp_attribute_string(_origin_vn,        _showroutepath, './origin_vn')
            _flags             = bgp_attribute_list(_flags,              _showroutepath, './flags/list/element')
            _sequence_no       = bgp_attribute_string(_sequence_no,      _showroutepath, './sequence_no')
            _tunnel_encap      = bgp_attribute_list(_tunnel_encap,       _showroutepath, './tunnel_encap/list/element')

            compute_source2nexthop(vn, _showroutepath, './source', './next_hop')

        all_prefix.update({     (evpn_prefix,
                                 _l2,
                                 _l3,
                                 controller
                                ) :
                                (
                                 _protocol.strip(),
                                 _last_modified.strip(),
                                 _local_preference.strip(),
                                 _med.strip(),
                                 _local_as.strip(),
                                 _peer_as.strip(),
                                 _peer_router_id.strip(),
                                 _source.strip(),
                                 _next_hop.strip(),
                                 _label.strip(),
                                 _replicated.strip(),
                                 _secondary_tables.strip(),
                                 _communities.strip(),
                                 _origin_vn.strip(),
                                 _flags.strip(),
                                 _sequence_no.strip(),
                                 _tunnel_encap.strip()
                                )})

      return(all_prefix)

#########################################################################
def get_l2_vrouter(vn, svs, sv_name):
  if options.brief_flag:
    header = [
                'mac',
                sv_name,
                'info_l3',
                'nh_sip',
                'nh_dip',
                'active_label',
                'vxlan_id',
                'active_tunnel_type',
                'preference',
          ]
  else:
    header = [
                'mac',
                sv_name,
                'info_l2',
                'info_l3',
                'info_adv',
                'nh_type',
                'nh_ref_count',
                'nh_sip',
                'nh_dip',
                #'nh_mac',
                'nh_tunnel_type',
                'active_label',
                'vxlan_id',
                'active_tunnel_type',
                'stale',
                'sequence',
                'preference',
                'ecmp',
          ]


  table = PrettyTable(header)
  prefix_count = defaultdict(list)
  all_prefix   = defaultdict(dict)
  for sv in svs:
    l2index = ""
    prefix_count[sv] = 0
    url = "http://%s:8085/Snh_PageReq?x=begin:-1,end:-1,table:db.vrf.0,"%(sv)
    print "In progress GET %s" %url
    error_flag = False
    try:
      response = urllib2.urlopen(url)
      data = unicode(response.read(), 'utf-8')
      response.close()
      root = etree.XML(data)
      vrfsandeshdatas = root.xpath('//VrfSandeshData')
      for vrfsandeshdata in vrfsandeshdatas:
        name = vrfsandeshdata.findtext('name')
        if vn.rt_instance == name:
          l2index = vrfsandeshdata.findtext('l2index')
          break
    except KeyboardInterrupt:
      wfr.close()
      sys.exit()
    except:
      print "Vrouterr VRF Get error"
      error_flag = True

    if error_flag == False:
      all_prefix = get_l2_vrouter_detail(sv, l2index, all_prefix, prefix_count)

  for key, value in sorted(all_prefix.items()):
    (
        _mac,
        sv,
        _info_l2,
        _info_l3,
        _info_adv,
    ) = key
    (
                _nh_type,
                _nh_ref_count,
                _nh_sip,
                _nh_dip,
                _nh_mac,
                _nh_tunnel_type,
                _active_label,
                _vxlan_id,
                _active_tunnel_type,
                _stale,
                _sequence,
                _preference,
                _ecmp
    ) = value
    if options.brief_flag:
      table.add_row([
                _mac,
                sv,
                _info_l3,
                _nh_sip,
                _nh_dip,
                _active_label,
                _vxlan_id,
                _active_tunnel_type,
                _preference,
                ])
    else:
      table.add_row([
                _mac,
                sv,
                _info_l2,
                _info_l3,
                _info_adv,
                _nh_type,
                _nh_ref_count,
                _nh_sip,
                _nh_dip,
                #_nh_mac,
                _nh_tunnel_type,
                _active_label,
                _vxlan_id,
                _active_tunnel_type,
                _stale,
                _sequence,
                _preference,
                _ecmp
                ])

  sys.stdout = open(wfr.result_file,"a+")
  print "\n"
  print "########## %s Sandesh ##########\n" %sv_name
  print datetime.datetime.today()
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print table
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print "\n"
  sys.stdout.close()
  sys.stdout = sys.__stdout__

  print "\n"
  print "########## %s Sandesh ##########\n" %sv_name
  print datetime.datetime.today()
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print table
  print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
  print "prefix count = %s" %sorted(prefix_count.items())
  print "\n"

#########################################################################
def get_l2_vrouter_detail(sv, l2index, all_prefix, prefix_count):
    if l2index != "":
      url = "http://%s:8085/Snh_Layer2RouteReq?vrf_index=%s&mac=&stale=" %(sv, l2index)
      while url:
        print "In progress GET %s" %url
        error_flag = False
        try:
          response = urllib2.urlopen(url)
          data = unicode(response.read(), 'utf-8')
          response.close()
        except KeyboardInterrupt:
          wfr.close()
          sys.exit()
        except:
          print "Vrouter Snh_Layer2RouteReq Get error"
          error_flag = True

        if ((response != None) & (error_flag == False)):
          root = etree.XML(data)
          all_prefix = parse_l2_vrouter(sv, root, all_prefix, prefix_count)

        nextpage = root.xpath('//next_page')[0].text
        if nextpage:
          nextpage  = urllib2.quote(nextpage.encode("utf-8"))
          url = "http://%s:8085/Snh_PageReq?x=%s" %(sv, nextpage)
        else:
          url = ""

    return(all_prefix)

#########################################################################
def parse_l2_vrouter(sv, root, all_prefix, prefix_count):
        routel2sandeshdatas = root.xpath('//RouteL2SandeshData')
        for routel2sadeshdata in routel2sandeshdatas:
          prefix_count[sv] += 1
          _mac = ""
          _info_l2 = ""
          _info_l3 = ""
          _info_adv = ""
          _nh_type = ""
          _nh_ref_count = ""
          _nh_sip = ""
          _nh_dip = ""
          _nh_mac = ""
          _nh_tunnel_type = ""
          _active_label = ""
          _vxlan_id = ""
          _active_tunnel_type = ""
          _stale = ""
          _info = ""
          _sequence = ""
          _preference = ""
          _ecmp = ""

          _mac = routel2sadeshdata.findtext('mac')
          _pathsandeshdatas = routel2sadeshdata.xpath('./path_list/list/PathSandeshData')
          for _pathsandeshdata in _pathsandeshdatas:
            _nh_type            = bgp_attribute_string(_nh_type,            _pathsandeshdata, './nh/NhSandeshData/type')
            _nh_ref_count       = bgp_attribute_string(_nh_ref_count,       _pathsandeshdata, './nh/NhSandeshData/ref_count')
            _nh_mac             = bgp_attribute_string(_nh_mac,             _pathsandeshdata, './nh/NhSandeshData/mac')
            if _mac == "ff:ff:ff:ff:ff:ff":
              _nh_tunnel_type     = bgp_attribute_string(_nh_tunnel_type,     _pathsandeshdata, './nh/NhSandeshData/mc_list/list/McastData/type')
              _nh_sip             = bgp_attribute_string(_nh_sip,             _pathsandeshdata, './nh/NhSandeshData/mc_list/list/McastData/sip')
              _nh_dip             = bgp_attribute_string(_nh_dip,             _pathsandeshdata, './nh/NhSandeshData/mc_list/list/McastData/dip')
            else:
              _nh_sip             = bgp_attribute_string(_nh_sip,             _pathsandeshdata, './nh/NhSandeshData/sip')
              _nh_dip             = bgp_attribute_string(_nh_dip,             _pathsandeshdata, './nh/NhSandeshData/dip')
              _nh_tunnel_type     = bgp_attribute_string(_nh_tunnel_type,     _pathsandeshdata, './nh/NhSandeshData/tunnel_type')
            _nh_tunnel_type     = bgp_attribute_string(_nh_tunnel_type,     _pathsandeshdata, './nh/NhSandeshData/tunnel_type')
            _active_label       = bgp_attribute_string(_active_label,       _pathsandeshdata, './active_label')
            _vxlan_id           = bgp_attribute_string(_vxlan_id,           _pathsandeshdata, './vxlan_id')
            _active_tunnel_type = bgp_attribute_string(_active_tunnel_type, _pathsandeshdata, './active_tunnel_type')
            _stale              = bgp_attribute_string(_stale,              _pathsandeshdata, './stale')
            _info               = bgp_attribute_string(_stale,              _pathsandeshdata, './info')
            _sequence           = bgp_attribute_string(_sequence,           _pathsandeshdata, './path_preference_data/PathPreferenceSandeshData/sequence')
            _preference         = bgp_attribute_string(_preference,         _pathsandeshdata, './path_preference_data/PathPreferenceSandeshData/preference')
            _ecmp               = bgp_attribute_string(_ecmp,               _pathsandeshdata, './path_preference_data/PathPreferenceSandeshData/ecmp')

            (_info_l2, _info_l3, _info_adv) = info_prefix_parse(_info)

          all_prefix.update({(
                                _mac,
                                sv,
                                _info_l2,
                                _info_l3,
                                _info_adv,
                        ):
                        (
                                 _nh_type.strip(),
                                 _nh_ref_count.strip(),
                                 _nh_sip.strip(),
                                 _nh_dip.strip(),
                                 _nh_mac.strip(),
                                 _nh_tunnel_type.strip(),
                                 _active_label.strip(),
                                 _vxlan_id.strip(),
                                 _active_tunnel_type.strip(),
                                 _stale.strip(),
                                 _sequence.strip(),
                                 _preference.strip(),
                                 _ecmp.strip(),
                        )})

        return(all_prefix)



#########################################################################
def get_vn(caller, credential, caller_b, vn):
  error_flag = False
  url = "/virtual-network/%s" %options.resource
  print "In progress GET %s" %url
  try:
    code, response = caller.get(url)
    time.sleep(api_wait_timer)
  except KeyboardInterrupt:
    wf.close()
    sys.exit()
  except:
    print "VN get error"
    print response
    error_flag = True

  if ((response != None) & (error_flag == False)):
    if options.output:
      wf.write(url)
      wf.writejson(response)
    header = ['vmi_uuid', 'vmi_mac', 'vmi_ip', 'lif_node', 'lif_port', 'vm_uuid', 'vm_hv', 'tap(maybe)', 'aap_ip', 'aap_mac']
    table = PrettyTable(header)

    _vmi_uuids = []
    try:
      _vn = response.get('virtual-network')
      vn.vn_pj           = _vn.get('fq_name')[1]
      vn.vn_name         = _vn.get('fq_name')[2]
      vn.vn_uuid         = _vn.get('uuid')
      vn.vn_vni          = _vn.get('virtual_network_network_id')
      vn.vn_is_dhcp      = _vn['network_ipam_refs'][0]['attr']['ipam_subnets'][0]['enable_dhcp']
      vn.vn_dhcp_address = _vn['network_ipam_refs'][0]['attr']['ipam_subnets'][0]['dns_server_address']
      ### for Sandesh ###
      _rt     = _vn.get('routing_instances')
      _rt_domain= _rt[0]['to'][0]
      _rt_pj    = _rt[0]['to'][1]
      _rt_vn    = _rt[0]['to'][2]
      _rt_name  = _rt[0]['to'][3]
      vn.rt_instance = "%s:%s:%s:%s" %(_rt_domain, _rt_pj, _rt_vn, _rt_name)
      vn.sandesh_rt_url = "Snh_ShowRouteReq?x=%s.evpn.0" %(vn.rt_instance)
      ###################

      for _vmi in _vn.get('virtual_machine_interface_back_refs'):
        _vmi_uuids.append(_vmi.get('uuid'))

    except:
      print "VN parse error"

    for vmi_uuid in _vmi_uuids:
      error_flag = False
      vmi_ip    = "-"
      vmi_mac   = "-"
      lif_node  = "-"
      lif_port  = "-"
      vm_uuid   = "-"
      vm_hv     = "-"
      vm_tap    = "-"
      aap_ip    = "-"
      aap_mac   = "-"
      dict_aap = {}

      url = "/virtual-machine-interface/%s" %vmi_uuid
      print "In progress GET %s" %url
      try:
        code, response = caller.get(url)
        time.sleep(api_wait_timer)
      except KeyboardInterrupt:
        wf.close()
        sys.exit()
      except:
        print "VMI get error"
        print response
        error_flag = True

      if ((response != None) & (error_flag == False)):
        if options.output:
          wf.write(url)
          wf.writejson(response)

        try:
          _vmi = response.get('virtual-machine-interface')
          vmi_mac = _vmi['virtual_machine_interface_mac_addresses']['mac_address'][0]
          if 'virtual_machine_interface_allowed_address_pairs' in _vmi:
            if 'allowed_address_pair' in _vmi['virtual_machine_interface_allowed_address_pairs']:
              aaps = _vmi['virtual_machine_interface_allowed_address_pairs']['allowed_address_pair']
              for aap in aaps:
               # print json.dumps(aap, indent=2, sort_keys=True)
                a = "%s/%s" %(aap['ip']['ip_prefix'], aap['ip']['ip_prefix_len'])
                b = aap['mac']
                dict_aap[a] = b

          ### for BM ###
          if 'logical_interface_back_refs' in _vmi:
            lif_node = _vmi['logical_interface_back_refs'][0]['to'][1]
            lif_port = _vmi['logical_interface_back_refs'][0]['to'][3]
          ### for compute ###
          if 'virtual_machine_refs' in _vmi:
            vm_uuid = _vmi['virtual_machine_refs'][0]['uuid']
            vm_tap = 'tap' + vmi_uuid[0:11]
            try:
              url_analytics = "/analytics/uves/virtual-machine/%s?flat" %vm_uuid
              code_b, response_b = caller_b.get(url_analytics)
              _uve_vm = response_b.get('UveVirtualMachineAgent')
              vm_hv = _uve_vm['vrouter']
              if isinstance(vm_hv, str) or isinstance(vm_hv, unicode):
                vn.compute_name_list.append(vm_hv)
            except:
              vm_hv = "unknown"

            if options.output:
              url = "/virtual-machine/%s" %vm_uuid
              print "In progress GET %s" %url
              try:
                code, response = caller.get(url)
                time.sleep(api_wait_timer)
              except KeyboardInterrupt:
                wf.close()
                sys.exit()
              except:
                print "VM get error"
                print response
                error_flag = True

              if ((response != None) & (error_flag == False)):
                wf.write(url)
                wf.writejson(response)
        except:
          print "VMI parse error"

        if 'instance_ip_back_refs' in _vmi:
          _vmi_ips = []
          for _instance_ip_back_ref in _vmi['instance_ip_back_refs']:
            _ip_uuid = _instance_ip_back_ref['uuid']
            url = "/instance-ip/%s" %_ip_uuid
            print "In progress GET %s" %url
            try:
              code, response = caller.get(url)
              time.sleep(api_wait_timer)
            except KeyboardInterrupt:
              wf.close()
              sys.exit()
            except:
              print "instance_ip get error"
              print response
              error_flag = True

            if ((response != None) & (error_flag == False)):
              if options.output:
                wf.write(url)
                wf.writejson(response)

              try:
                _ip = response.get('instance-ip')
                if 'instance_ip_address' in _ip:
                  _vmi_ips.append(_ip.get('instance_ip_address'))
                else:
                  _vmi_ips.append("null")
              except:
                print "instance_ip parse error"
          vmi_ip = "\n".join(sorted(_vmi_ips))

      table.sortby = 'vmi_ip'
      table.align = 'l'
      table.reversesort = False
      if len(dict_aap):
        aap_ip  = ""
        aap_mac = ""
        for k,v in dict_aap.items():
          aap_ip  = aap_ip  + k + "\n"
          aap_mac = aap_mac + v + "\n"
      table.add_row([vmi_uuid, vmi_mac, vmi_ip, lif_node, lif_port, vm_uuid, vm_hv, vm_tap, aap_ip.strip(), aap_mac.strip()])

    if options.route_get_flag:
      sys.stdout = open(wfr.result_file,"a+")
    print "\n"
    print "########## Config ##########\n"
    print datetime.datetime.today()
    print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
    print table
    print "project = %s, vn = %s, vn_uuid = %s, vni = %s, dhcp = %s, dns_address = %s" %(vn.vn_pj, vn.vn_name, vn.vn_uuid, vn.vn_vni, vn.vn_is_dhcp, vn.vn_dhcp_address)
    print "\n"
    if options.route_get_flag:
      sys.stdout = open(wfr.result_file,"a+")
      sys.stdout.close()
      sys.stdout = sys.__stdout__
      os.system('cat %s' %wfr.result_file)

#########################################################################
def initialize_options():
    parser = OptionParser()
    parser.add_option('-t', '--target', dest='target', type='string', action="store",
            default=TARGET, help='Target host')
    parser.add_option('-n', '--analytics', dest='analytics', type='string', action="store",
            default=ANALYTICS, help='Analytics Target host')
    parser.add_option('-p', '--port', dest='port', type='string', action="store",
            default='8082', help='Target port (Default 8082)')
    parser.add_option('-a', '--api', dest='api', type='string', action="store",
            default=API_DEFAULT, help='API class')
    parser.add_option('-u', '--username', dest='username', type='string', action="store",
            default=USER , help='User name')
    parser.add_option('-P', '--password', dest='password', type='string', action="store",
            default=PASSWORD , help='Password')
    parser.add_option('-J', '--project', dest='tenant', type='string', action="store",
            default=TENANT , help='Tenant name')
    parser.add_option('-A', '--auth_port', dest='auth_port', type='string', action="store",
            default=AUTH_API_DEFAULT, help='IAM Port (Default %d)' % AUTH_API_DEFAULT)
    parser.add_option('-m', '--method', dest='method', type='string', action="store",
            help='Method')
    parser.add_option('-r', '--resource', dest='resource', type='string', action="store",
            help='Resource')
    parser.add_option('-K', '--keystone', dest='keystone_host', type='string', action="store",
            default=KEYSTONE, help='Keystone host')
    parser.add_option('-v', '--keystone_ver', dest='keystone_ver', type='string', action="store",
            default=KEYSTONE_VER, help='Keystone host')
    parser.add_option('-b', '--body', dest='body', type='string', action="store", help='Body')

    parser.add_option('-O', '--output', dest='output', action="store_true",
            default=False, help='output to FILE (Default False)')
    parser.add_option('-R', '--route', dest='route_get_flag', action="store_true",
            default=False, help='output to FILE (Default False)')
    parser.add_option('-C', '--route-compute', dest='route_get_compute_flag', action="store_true",
            default=False, help='output to FILE (Default False)')
    parser.add_option('-B', '--brief', dest='brief_flag', action="store_true",
            default=False, help='brief')

    return parser.parse_args()

########## Sandesh Prefix Parser ###########

class VnArgs:
  def __init__(self):
    self.vn_pj   = ""
    self.vn_name = ""
    self.vn_uuid = ""
    self.vn_vni  = ""
    self.rt_instance = ""
    self.sandesh_rt_url = ""
    self.vn_is_dhcp  = True
    self.vn_dhcp_address  = ""
    self.compute_name_list = []
    self.compute_name2ip = {}

#########################################################################
def main(options, remain):
  vn         = VnArgs()
  credential = KeystoneCredential(options.keystone_host, options.auth_port, options.username, options.password, options.tenant)
  caller           = ApiCaller.create(api_class=options.api, host=options.target, port=options.port)
  caller.login(credential)
  caller_b   = ApiCaller.create(api_class=options.api, host=options.analytics, port="8081")
  print "Token Expires = %s" %credential._token_expiry
  print "Token         = %s" %credential._authn_token
  print ""
  get_vn(caller,credential, caller_b, vn)
  vn.compute_name_list = list(set(vn.compute_name_list))
  if options.route_get_flag or options.route_get_tsn_flag or options.route_get_compute_flag:
    get_l2_ctrl(vn)
  if options.route_get_compute_flag:
    get_l2_vrouter(vn, vn.compute_name2ip.values(), "Compute")

#########################################################################

if __name__ == '__main__':
  print datetime.datetime.today()
  options, remain = initialize_options()
  time_str = datetime.datetime.today().strftime("%Y%m%d%H%M%S")

  if options.output:
    save_file = "contrail_get_json"
    wf = WriteFile(save_file, time_str)
    wf.open()
    wf.write(time_str)

  if options.route_get_flag or options.route_get_tsn_flag or options.route_get_compute_flag:
    save_file = "contrail_Snh_route"
    wfr = WriteFile(save_file, time_str)

  main(options, remain)

  if options.output:
    wf.close()

#########################################################################

