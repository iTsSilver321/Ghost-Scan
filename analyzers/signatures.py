# Regex signatures for service and OS detection
# Format: (Regex Pattern, Product Name, Category, OS/Extra Info)
# Category: 'ver' (Version), 'os' (Operating System), 'app' (Application)

SIGNATURES = [
    # HTTP Servers
    (r"Apache/([\d\.]+)", "Apache httpd", "ver", "Unix/Linux"),
    (r"nginx/([\d\.]+)", "nginx", "ver", "Linux"),
    (r"Microsoft-IIS/([\d\.]+)", "Microsoft IIS", "ver", "Windows"),
    (r"lighttpd/([\d\.]+)", "lighttpd", "ver", "Unix/Linux"),
    (r"Python/([\d\.]+)", "Python HTTP", "ver", "Cross-Platform"),
    (r"Werkzeug/([\d\.]+)", "Werkzeug WSGI", "ver", "Python"),
    
    # SSH
    (r"OpenSSH_([\d\.]+)", "OpenSSH", "ver", "Unix/Linux"),
    (r"Dropbear_([\d\.]+)", "Dropbear SSH", "ver", "Embedded Linux"),
    (r"libssh/([\d\.]+)", "libssh", "ver", "Cross-Platform"),
    
    # FTP
    (r"vsFTPd ([\d\.]+)", "vsFTPd", "ver", "Unix/Linux"),
    (r"FileZilla Server ([\d\.]+)", "FileZilla Server", "ver", "Windows"),
    
    # OS Keywords (Passive)
    (r"Ubuntu", "Ubuntu Linux", "os", "Linux"),
    (r"Debian", "Debian Linux", "os", "Linux"),
    (r"CentOS", "CentOS Linux", "os", "Linux"),
    (r"Windows", "Windows", "os", "Windows"),
    (r"FreeBSD", "FreeBSD", "os", "BSD"),
    
    # Specific Devices
    (r"ZTE web server", "ZTE Router", "app", "Embedded"),
    (r"Hikvision", "Hikvision Camera", "app", "Embedded"),
]
