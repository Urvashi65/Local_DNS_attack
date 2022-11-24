$TTL 3D
@       IN      SOA   ns.seedattacker123.com. admin.seedattacker123.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.seedattacker123.com.

@       IN      A     10.9.0.180
www     IN      A     10.9.0.180
ns      IN      A     10.9.0.153
*       IN      A     10.9.0.100
