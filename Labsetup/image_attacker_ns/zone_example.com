$TTL 3D
@       IN      SOA   ns.practice.com. admin.practice.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.seedattacker123.com.

@       IN      A     1.2.3.4
www     IN      A     1.2.3.5
ns      IN      A     10.9.0.153
*       IN      A     1.2.3.6
