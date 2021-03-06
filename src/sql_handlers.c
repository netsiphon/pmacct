/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __SQL_HANDLERS_C

/*
  PG_* functions are used only by PostgreSQL plugin;
  MY_* functions are used only by MySQL plugin;
  count_* functions are used by more than one plugin;
  fake_* functions are used to supply static zero-filled values;
*/ 

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "ip_flow.h"
#include "classifier.h"

static const char fake_mac[] = "0:0:0:0:0:0";
static const char fake_host[] = "0.0.0.0";
static const char fake_as[] = "0";
static const char fake_comm[] = "";
static const char fake_as_path[] = "";

/* Functions */
#if defined (HAVE_L2)
void count_src_mac_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char sbuf[18];
  u_int8_t ubuf[ETH_ADDR_LEN];

  memcpy(&ubuf, &cache_elem->primitives.eth_shost, ETH_ADDR_LEN);
  etheraddr_string(ubuf, sbuf);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_mac_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char sbuf[18];
  u_int8_t ubuf[ETH_ADDR_LEN];

  memcpy(ubuf, &cache_elem->primitives.eth_dhost, ETH_ADDR_LEN);
  etheraddr_string(ubuf, sbuf);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_vlan_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.vlan_id);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.vlan_id);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_cos_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.cos);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.cos);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_etype_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.etype);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.etype);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
#endif

void count_src_host_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_net_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.src_net);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_as_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.dst_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_net_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.dst_net);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_as_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_in_iface_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.ifindex_in);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.ifindex_in);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_out_iface_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.ifindex_out);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.ifindex_out);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_nmask_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_nmask);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_nmask);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_nmask_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_nmask);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_nmask);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

#if defined WITH_GEOIP
void count_src_host_country_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, GeoIP_code_by_id(cache_elem->primitives.src_ip_country.id));
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, GeoIP_code_by_id(cache_elem->primitives.src_ip_country.id));
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_country_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, GeoIP_code_by_id(cache_elem->primitives.dst_ip_country.id));
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, GeoIP_code_by_id(cache_elem->primitives.dst_ip_country.id));
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
#endif
#if defined WITH_GEOIPV2
void count_src_host_country_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_ip_country.str);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_ip_country.str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_country_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_ip_country.str);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_ip_country.str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
#endif

void count_sampling_rate_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.sampling_rate);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.sampling_rate);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_pkt_len_distrib_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, idata->cfg->pkt_len_distrib_bins[cache_elem->primitives.pkt_len_distrib]);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, idata->cfg->pkt_len_distrib_bins[cache_elem->primitives.pkt_len_distrib]);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_src_ip_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pnat->post_nat_src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_dst_ip_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pnat->post_nat_dst_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_src_port_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->post_nat_src_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->post_nat_src_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_dst_port_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->post_nat_dst_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->post_nat_dst_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_nat_event_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->nat_event);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->nat_event);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_mpls_label_top_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pmpls->mpls_label_top);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pmpls->mpls_label_top);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_mpls_label_bottom_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pmpls->mpls_label_bottom);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pmpls->mpls_label_bottom);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_mpls_stack_depth_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pmpls->mpls_stack_depth);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pmpls->mpls_stack_depth);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_copy_count_timestamp_start_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char time_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->pnat->timestamp_start.tv_sec);
  strftime(time_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_start.tv_sec); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_start_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_start.tv_sec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_start.tv_sec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_start_residual_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_start.tv_usec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_start.tv_usec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_copy_count_timestamp_end_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char time_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->pnat->timestamp_end.tv_sec);
  strftime(time_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_end.tv_sec); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_end_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_end.tv_sec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_end.tv_sec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_end_residual_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_end.tv_usec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_end.tv_usec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_copy_count_timestamp_arrival_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char time_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->pnat->timestamp_arrival.tv_sec);
  strftime(time_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_arrival.tv_sec); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_arrival_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_arrival.tv_sec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_arrival.tv_sec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_arrival_residual_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_arrival.tv_usec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_arrival.tv_usec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_copy_count_timestamp_min_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char time_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->stitch->timestamp_min.tv_sec);
  strftime(time_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->stitch->timestamp_min.tv_sec); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_min_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->stitch->timestamp_min.tv_sec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->stitch->timestamp_min.tv_sec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_min_residual_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->stitch->timestamp_min.tv_usec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->stitch->timestamp_min.tv_usec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_copy_count_timestamp_max_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char time_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->stitch->timestamp_max.tv_sec);
  strftime(time_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->stitch->timestamp_max.tv_sec); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_max_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->stitch->timestamp_max.tv_sec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->stitch->timestamp_max.tv_sec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_max_residual_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->stitch->timestamp_max.tv_usec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->stitch->timestamp_max.tv_usec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_export_proto_seqno_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.export_proto_seqno);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.export_proto_seqno);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_export_proto_version_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.export_proto_version);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.export_proto_version);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_custom_primitives_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  struct custom_primitive_ptrs *cp_entry;
  char cp_str[SRVBUFLEN];

  cp_entry = &config.cpptrs.primitive[idata->cp_idx];

  if (cp_entry->ptr->len != PM_VARIABLE_LENGTH) {
    char cp_str[SRVBUFLEN];

    custom_primitive_value_print(cp_str, SRVBUFLEN, cache_elem->pcust, cp_entry, FALSE);
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cp_str);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cp_str);
  }
  else {
    char *label_ptr = NULL, empty_string[] = "";

    vlen_prims_get(cache_elem->pvlen, cp_entry->ptr->type, &label_ptr);
    if (!label_ptr) label_ptr = empty_string;
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, label_ptr);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, label_ptr);
  }

  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);

  idata->cp_idx++;
  idata->cp_idx %= config.cpptrs.num;
}

void count_std_comm_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *bgp_comm_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_STD_COMM, &bgp_comm_ptr);
  if (!bgp_comm_ptr) bgp_comm_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, bgp_comm_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, bgp_comm_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_ext_comm_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *bgp_comm_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_EXT_COMM, &bgp_comm_ptr);
  if (!bgp_comm_ptr) bgp_comm_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, bgp_comm_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, bgp_comm_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_lrg_comm_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *bgp_comm_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_LRG_COMM, &bgp_comm_ptr);
  if (!bgp_comm_ptr) bgp_comm_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, bgp_comm_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, bgp_comm_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_as_path_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *as_path_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_AS_PATH, &as_path_ptr);
  if (!as_path_ptr) as_path_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, as_path_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, as_path_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_std_comm_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *bgp_comm_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_SRC_STD_COMM, &bgp_comm_ptr);
  if (!bgp_comm_ptr) bgp_comm_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, bgp_comm_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, bgp_comm_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_ext_comm_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *bgp_comm_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_SRC_EXT_COMM, &bgp_comm_ptr);
  if (!bgp_comm_ptr) bgp_comm_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, bgp_comm_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, bgp_comm_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_lrg_comm_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *bgp_comm_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_SRC_LRG_COMM, &bgp_comm_ptr);
  if (!bgp_comm_ptr) bgp_comm_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, bgp_comm_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, bgp_comm_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_as_path_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *as_path_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_SRC_AS_PATH, &as_path_ptr);
  if (!as_path_ptr) as_path_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, as_path_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, as_path_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_local_pref_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pbgp->local_pref);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pbgp->local_pref);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_local_pref_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pbgp->src_local_pref);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pbgp->src_local_pref);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_med_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pbgp->med);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pbgp->med);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_med_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pbgp->src_med);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pbgp->src_med);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_mpls_vpn_rd_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[SRVBUFLEN];

  bgp_rd2str(ptr, &cache_elem->pbgp->mpls_vpn_rd);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_src_as_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pbgp->peer_src_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pbgp->peer_src_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_dst_as_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pbgp->peer_dst_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pbgp->peer_dst_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_src_ip_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pbgp->peer_src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_dst_ip_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN], *indirect_ptr = ptr;

  addr_to_str(ptr, &cache_elem->pbgp->peer_dst_ip);
  if (!strlen(ptr)) indirect_ptr = (char *) fake_host;
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, indirect_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, indirect_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_port_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_port_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_tcpflags_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->tcp_flags);
  *ptr_values += strlen(*ptr_values);
}

void count_ip_tos_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.tos);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.tos);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}




  
  
  
  
  
  
  
  
  
  


void count_packet_payload_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  int primitive_length = sizeof(cache_elem->primitives.packet_payload);
  int payload_length, check_length, base, multiplier, remainder;
  char extract_length[8];
  char *payload_ptr;
  
  payload_ptr = (char *) &cache_elem->primitives.packet_payload[primitive_length - 8];
  memset(extract_length, 0, sizeof(extract_length) - 1);
  memcpy(extract_length, payload_ptr, sizeof(extract_length) - 1); 
  
  sscanf(extract_length, "%i", &check_length);
  //printf("check length:%d \n\n",check_length);
  if (check_length >= 2 && check_length <=1355) {
    if (check_length < primitive_length) 
	  {
		payload_length = check_length;
	  } 
	  else {
		payload_length = primitive_length;
	  }
	  char packet_payload[payload_length];
	  memset(packet_payload, 0, sizeof(packet_payload));
	  
	  memcpy(packet_payload, cache_elem->primitives.packet_payload, payload_length);
	  packet_payload[payload_length] = '\0';
	  
	  char *buf;
	  int hex_length = (payload_length*2) - 1;
	  buf = calloc(hex_length, sizeof(char));
	  memset(buf, 0, hex_length);

	  //print_payload(packet_payload, payload_length);
	  
	  //printf("PacketSize: %d \n",payload_length);
	  buf = fasthex(packet_payload, payload_length);
	  
	  buf[hex_length - 1] = '\0';
	  //printf("%s\n", buf);
  
  
	  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, buf);
	  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, buf);
	  *ptr_where += strlen(*ptr_where);
	  *ptr_values += strlen(*ptr_values);
  } else {
	  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, "");
	  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, "");
	  *ptr_where += strlen(*ptr_where);
	  *ptr_values += strlen(*ptr_values);
  }
}

void count_packet_header_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  int primitive_length = sizeof(cache_elem->primitives.packet_header);
  int header_length, check_length;

  
  check_length = (int)cache_elem->primitives.packet_header[primitive_length - 2];
  
  if (check_length >= 2 && check_length <=129) {
    if (check_length < primitive_length) 
	  {
		header_length = check_length;
	  } 
	  else {
		header_length = primitive_length;
	  }
	  char packet_header[header_length];
	  memset(packet_header, 0, sizeof(packet_header));
	  
	  memcpy(packet_header, cache_elem->primitives.packet_header, header_length - 1);
	  packet_header[header_length - 1] = '\0';
	  
	  char *buf;
	  int hex_length = (header_length*2) - 1;
	  buf = calloc(hex_length, sizeof(char));
	  memset(buf, 0, hex_length);

	  //print_payload(packet_header, header_length);
	  
	  //printf("PacketHeaderSize: %d \n",header_length);
	  buf = fasthex(packet_header, header_length);
	  
	  buf[hex_length - 1] = '\0';
	  //printf("%s\n", buf);
  
  
	  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, buf);
	  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, buf);
	  *ptr_where += strlen(*ptr_where);
	  *ptr_values += strlen(*ptr_values);
   } else {
	  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, "");
	  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, "");
	  *ptr_where += strlen(*ptr_where);
	  *ptr_values += strlen(*ptr_values);
  }
}


void count_unique_packet_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.unique_packet);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.unique_packet);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}


void MY_count_ip_proto_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  if (cache_elem->primitives.proto < protocols_number) {
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, _protocols[cache_elem->primitives.proto].name);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, _protocols[cache_elem->primitives.proto].name);
  }
  else {
    char proto_str[PROTO_LEN];

    snprintf(proto_str, sizeof(proto_str), "%d", cache_elem->primitives.proto);
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, proto_str);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, proto_str);
  }
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_count_ip_proto_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.proto);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.proto);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_copy_timestamp_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char btime_str[LONGSRVBUFLEN], now_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->basetime);
  strftime(btime_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  tme = localtime(&idata->now);
  strftime(now_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);
  
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->basetime); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, now_str, btime_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  time_t tme = idata->now;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->basetime);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, tme, cache_elem->basetime);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_tag_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.tag);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.tag);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_tag2_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.tag2);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.tag2);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_label_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *label_ptr = NULL, empty_string[] = "";

  vlen_prims_get(cache_elem->pvlen, COUNT_INT_LABEL, &label_ptr);
  if (!label_ptr) label_ptr = empty_string;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, label_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, label_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_class_id_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char buf[MAX_PROTOCOL_LEN+1];

  memset(buf, 0, MAX_PROTOCOL_LEN+1);
  if (cache_elem->primitives.class && class[cache_elem->primitives.class-1].id) {
    strlcpy(buf, class[cache_elem->primitives.class-1].protocol, MAX_PROTOCOL_LEN);
    buf[sizeof(buf)-1] = '\0';
  }
  else strlcpy(buf, "unknown", MAX_PROTOCOL_LEN);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, buf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, buf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_counters_setclause_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  snprintf(*ptr_set, SPACELEFT(set_clause), set[num].string, cache_elem->packet_counter, cache_elem->bytes_counter);
  *ptr_set  += strlen(*ptr_set);
}

void count_flows_setclause_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  snprintf(*ptr_set, SPACELEFT(set_clause), set[num].string, cache_elem->flows_counter);
  *ptr_set  += strlen(*ptr_set);
}

void count_tcpflags_setclause_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  snprintf(*ptr_set, SPACELEFT(set_clause), set[num].string, cache_elem->tcp_flags);
  *ptr_set  += strlen(*ptr_set);
}

void count_noop_setclause_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  strncpy(*ptr_set, set[num].string, SPACELEFT(set_clause));
  *ptr_set  += strlen(*ptr_set);
}

void count_noop_setclause_event_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  strncpy(*ptr_set, set_event[num].string, SPACELEFT(set_clause));
  *ptr_set  += strlen(*ptr_set);
}

/* Fake handlers next */ 
void fake_mac_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_mac);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_mac);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_host_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_host);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_host);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_as_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_comms_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_comm);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_comm);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_as_path_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_as_path);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_as_path);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_host_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " "; 
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.src_ip);
  if (cache_elem->primitives.src_ip.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->primitives.src_ip.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;
  
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " ";
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.dst_ip);
  if (cache_elem->primitives.dst_ip.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->primitives.dst_ip.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_net_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " ";
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.src_net);
  if (cache_elem->primitives.src_net.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->primitives.src_net.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_net_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " ";
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.dst_net);
  if (cache_elem->primitives.dst_net.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->primitives.dst_net.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_src_ip_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " ";
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pbgp->peer_src_ip);
  if (cache_elem->pbgp->peer_src_ip.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->pbgp->peer_src_ip.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_dst_ip_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " ";
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pbgp->peer_dst_ip);
  if (cache_elem->pbgp->peer_dst_ip.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->pbgp->peer_dst_ip.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_src_ip_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " ";
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pnat->post_nat_src_ip);
  if (cache_elem->pnat->post_nat_src_ip.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->pnat->post_nat_src_ip.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_dst_ip_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON", aton_null[] = " ";
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pnat->post_nat_dst_ip);
  if (cache_elem->pnat->post_nat_dst_ip.family == AF_INET) aton = aton_v4;
#if defined ENABLE_IPV6
  else if (cache_elem->pnat->post_nat_dst_ip.family == AF_INET6) aton = aton_v6;
#endif
  else aton = aton_null;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_host_aton_handler(const struct db_cache *cache_elem, struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char *aton = NULL, aton_v4[] = "INET_ATON", aton_v6[] = "INET6_ATON";

  aton = aton_v4;
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, aton, fake_host);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, aton, fake_host);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

char btoh(const u_char *payload, int len )
{
	u_char *retchar, *buf;
	u_char const *pos,*end;
	
	end = payload + sizeof(payload);
	
	while (payload < end)
	{
		sprintf(retchar,"%02x",payload);
		//*retchar = fasthex(payload,sizeof(payload));
		retchar++;
		payload++;
	}

	return *retchar;
}

/* The following functions were borrowed from Snort 2.6.1.1 source*/
char *fasthex(u_char *xdata, int length)
{
    char conv[] = "0123456789ABCDEF";
    char *retbuf = NULL; 
    char *index;
    char *end;
    char *ridx;

    index = xdata;
    end = xdata + length;
    retbuf = calloc((length*2)+1, sizeof(char));
    ridx = retbuf;

    while(index < end)
    {
        *ridx++ = conv[((*index & 0xFF)>>4)];
        *ridx++ = conv[((*index & 0xFF)&0x0F)];
        index++;
    }

    return retbuf;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

