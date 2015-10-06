consul = "consul:8500"
token = "the_one_ring"

template {
  source = "/config/kamailio.ctmpl"
  destination  = "/etc/kamailio/dispatcher.list"
  command = "pkill -9 kamailio; kamailio"
}
