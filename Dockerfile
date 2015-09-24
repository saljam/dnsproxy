from scratch
maintainer Salman Aljammaz <s@jmz.io>

add dnsproxy /

expose 5556
cmd ["/dnsproxy", "-remote", "-tunnel-addr", ":5556"]
