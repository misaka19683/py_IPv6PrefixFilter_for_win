import pydivert
from scapy.all import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

# 设置目标前缀
target_prefix = "2001:db8::"

# 设置 WinDivert 过滤器
w = pydivert.WinDivert("icmp6.Type == 134")
w.open()

try:
    while True:
        packet = w.recv()  # 捕获数据包
        packet_bytes = packet.tobytes()  # 转换为字节形式

        try:
            # 使用 Scapy 解析数据包
            scapy_packet = IPv6(packet_bytes)

            # 检查是否是路由通告
            if scapy_packet.haslayer(ICMPv6ND_RA):
                ra_packet = scapy_packet[ICMPv6ND_RA]
                print(f"Router Advertisement: Code = {ra_packet.code}, Chlim = {ra_packet.chlim}")

                # 跟踪是否匹配目标前缀
                prefix_matched = False

                # 查找前缀信息选项
                for option in scapy_packet[ICMPv6NDOptPrefixInfo]:
                    if isinstance(option, ICMPv6NDOptPrefixInfo):
                        print("Prefix Info:")
                        print(f"  Prefix: {option.prefix}")
                        print(f"  Prefix Length: {option.prefixlen}")
                        print(f"  Valid Lifetime: {option.validlifetime}")
                        print(f"  Preferred Lifetime: {option.preferredlifetime}")

                        # 比对目标前缀
                        if str(option.prefix).startswith(target_prefix):
                            print(f"Match found with target prefix: {target_prefix}")
                            prefix_matched = True
                            break  # 匹配成功，停止检查其他选项

                # 根据匹配结果决定是否重新注入数据包
                if prefix_matched:
                    w.send(packet)  # 重新注入数据包
                else:
                    print("Prefix does not match. Dropping the packet.")

        except Exception as e:
            print(f"Error parsing packet: {e}")

except KeyboardInterrupt:
    print("Stopping packet capture.")
finally:
    w.close()
