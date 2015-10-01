consul = "consul:8500"
token = "the_one_ring"

template {
  source = "/config/ha-proxy.ctmpl"
  destination  = "/usr/local/etc/haproxy/haproxy.cfg"
  command = "haproxy -f /usr/local/etc/haproxy/haproxy.cfg -p /var/run/haproxy/haproxy.pid -sf $(cat /var/run/haproxy/haproxy.pid)"
}
