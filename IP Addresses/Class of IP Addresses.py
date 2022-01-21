
def getIPClass(ip):
    ip_class = int(ip.split(".")[0].strip())
    if ip_class <= 127:
        return "A"
    elif ip_class <= 191:
        return "B"
    elif ip_class <= 223:
        return "C"
    elif ip_class <= 239:
        return "D"
    elif ip_class <= 255:
        return "E"

print(getIPClass("125.59.58.128"))
print(getIPClass("168.212.226.204"))
print(getIPClass("192.168.178.1"))
print(getIPClass("227.21.6.173"))
print(getIPClass("243.164.89.28"))
