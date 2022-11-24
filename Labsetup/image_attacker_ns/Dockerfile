FROM handsonsecurity/seed-server:bind

# Copy the configuration and zone files
COPY named.conf  zone_seedattacker123.com  zone_practice.com  /etc/bind/

CMD service named start && tail -f /dev/null
