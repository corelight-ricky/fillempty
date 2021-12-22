event connection_state_remove(c: connection) &priority=1
        {
                if (!c$conn?$service)
                        c$conn$service = "--";
                if (!c$conn?$duration)
                        c$conn$duration = 0sec;
                if (!c$conn?$orig_bytes)
                        c$conn$orig_bytes = 0;
                if (!c$conn?$resp_bytes)
                        c$conn$resp_bytes = 0;
                if (!c$conn?$conn_state)
                        c$conn$conn_state = "--";
                if (!c$conn?$local_orig)
                        c$conn$local_orig = F;
                if (!c$conn?$local_resp)
                        c$conn$local_resp = F;
                if (!c$conn?$history)
                        c$conn$history = "--";
                if (!c$conn?$orig_pkts)
                        c$conn$orig_pkts = 0;
                if (!c$conn?$orig_ip_bytes)
                        c$conn$orig_ip_bytes = 0;
                if (!c$conn?$resp_pkts)
                        c$conn$resp_pkts = 0;
                if (!c$conn?$resp_ip_bytes)
                        c$conn$resp_ip_bytes = 0;
                if (!c$conn?$tunnel_parents)
                        c$conn$tunnel_parents = ["--"];
        }

event dns_end(c: connection, msg: dns_msg) &priority=1
        {
        if (c?$dns)
                {
                if (!c$dns?$trans_id)
                        c$dns$trans_id = 0;
                if (!c$dns?$rtt)
                        c$dns$rtt = 0msec;
                if (!c$dns?$query)
                        c$dns$query = "--";
                if (!c$dns?$qclass)
                        c$dns$qclass = 0;
                if (!c$dns?$qclass_name)
                        c$dns$qclass_name = "--";
                if (!c$dns?$qtype)
                        c$dns$qtype = 0;
                if (!c$dns?$qtype_name)
                        c$dns$qtype_name = "--";
                if (!c$dns?$rcode)
                        c$dns$rcode = 0;
                if (!c$dns?$rcode_name)
                        c$dns$rcode_name = "--";
                if (!c$dns?$answers)
                        c$dns$answers = ["--"];
                if (!c$dns?$TTLs)
                        c$dns$TTLs = [0sec];
                if (!c$dns?$total_answers)
                        c$dns$total_answers = 0;
                if (!c$dns?$total_replies)
                        c$dns$total_replies = 0;

                }
        }

hook SSL::ssl_finishing(c: connection) &priority = -5
        {
                if (!c$ssl?$version)
                        c$ssl$version = "--";
                if (!c$ssl?$cipher)
                        c$ssl$cipher = "--";
                if (!c$ssl?$curve)
                        c$ssl$curve = "--";
                if (!c$ssl?$server_name)
                        c$ssl$server_name = "--";
                if (!c$ssl?$last_alert)
                        c$ssl$last_alert = "--";
                if (!c$ssl?$next_protocol)
                        c$ssl$next_protocol = "--";
                }
