pcaplocation='/opt/zeek/share/btest/data/pcaps/tls/ecdhe.pcap'
echo "executing zeek -C -r $pcaplocation test.zeek"
echo "using premade packet capture (pcap) file from dir $pcapdir"
zeek -C -r $pcapdir/tls/ecdhe.pcap test.zeek
cat netcontrol.log
