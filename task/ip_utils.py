import re
from typing import Optional, Tuple


class IPInfo:
    """Структура для хранения и представления IP-адреса"""

    def __init__(
        self,
        version: int,
        address_int: int,
        prefix_len: Optional[int] = None,
        zone: Optional[str] = None,
    ):
        self.version = version
        self.address_int = address_int
        self.prefix_len = prefix_len
        self.zone = zone
        self.max_bits = 32 if version == 4 else 128

    @property
    def hex(self) -> str:
        if self.version == 4:
            return f"{self.address_int:08X}"
        else:
            return f"{self.address_int:032X}"

    def _format_address(self) -> str:
        if self.version == 4:
            parts = [(self.address_int >> (8 * i)) & 0xFF for i in range(3, -1, -1)]
            return ".".join(map(str, parts))
        else:
            groups = [(self.address_int >> (16 * i)) & 0xFFFF for i in range(7, -1, -1)]
            group_strs = [f"{g:04x}" for g in groups]

            best_start, best_len = -1, 0
            cur_start = -1
            for i, g in enumerate(group_strs):
                if g == "0000":
                    if cur_start == -1:
                        cur_start = i
                else:
                    if cur_start != -1:
                        length = i - cur_start
                        if length > best_len:
                            best_len, best_start = length, cur_start
                        cur_start = -1
            if cur_start != -1:
                length = len(group_strs) - cur_start
                if length > best_len:
                    best_len, best_start = length, cur_start

            if best_len > 1:
                left = group_strs[:best_start]
                right = group_strs[best_start + best_len :]
                left = [f"{int(x, 16):x}" for x in left]
                right = [f"{int(x, 16):x}" for x in right]
                left_str = ":".join(left) if left else ""
                right_str = ":".join(right) if right else ""
                if left_str == "" and right_str == "":
                    return "::"
                elif left_str == "":
                    return f"::{right_str}"
                elif right_str == "":
                    return f"{left_str}::"
                else:
                    return f"{left_str}::{right_str}"
            else:
                return ":".join(group_strs)

    def to_netmask(self) -> str:
        if self.prefix_len is None:
            raise ValueError("Не задана длина префикса для формирования маски")
        if self.version == 4:
            if self.prefix_len == 0:
                return "0.0.0.0"
            mask_int = (0xFFFFFFFF << (32 - self.prefix_len)) & 0xFFFFFFFF
            parts = [(mask_int >> (8 * i)) & 0xFF for i in range(3, -1, -1)]
            return ".".join(map(str, parts))
        else:
            if self.prefix_len == 0:
                return "::"
            mask_int = (
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF << (128 - self.prefix_len)
            ) & ((1 << 128) - 1)
            temp = IPInfo(6, mask_int)
            return temp._format_address()

    def to_string(self, with_prefix: bool = False) -> str:
        base = self._format_address()
        if with_prefix and self.prefix_len is not None:
            return f"{base}/{self.prefix_len}"
        return base

    def __str__(self) -> str:
        return self.to_string(with_prefix=True)

    def __repr__(self):
        parts = [
            f"version={self.version}",
            f"address_int={self.address_int:#0{10 if self.version==4 else 34}x}",
        ]
        if self.prefix_len is not None:
            parts.append(f"prefix={self.prefix_len}")
        if self.zone:
            parts.append(f"zone={self.zone}")
        return f"IPInfo({', '.join(parts)})"


# --------------------------------------------------------------
# Вспомогательные функции парсинга
# --------------------------------------------------------------


def _parse_ipv4(s: str) -> IPInfo:
    s = s.strip()

    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/([^\s]+))?$", s)
    if not m:
        raise ValueError(f"Некорректный формат IPv4: {s}")

    octets = [int(m.group(i)) for i in range(1, 5)]
    for o in octets:
        if o > 255:
            raise ValueError(f"Октет {o} вне диапазона 0-255 в {s}")

    address_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    prefix_str = m.group(5)
    prefix_len = None

    if prefix_str is not None:
        if prefix_str.isdigit():
            prefix_len = int(prefix_str)
            if prefix_len > 32:
                raise ValueError(
                    f"Префикс IPv4 должен быть 0-32, получено {prefix_len}"
                )
        else:
            mask_parts = prefix_str.split(".")
            if len(mask_parts) != 4 or not all(p.isdigit() for p in mask_parts):
                raise ValueError(f"Некорректная маска подсети: {prefix_str}")

            mask_octets = [int(p) for p in mask_parts]
            if any(o > 255 for o in mask_octets):
                raise ValueError(f"Октет маски вне диапазона 0-255: {prefix_str}")

            mask_int = (
                (mask_octets[0] << 24)
                | (mask_octets[1] << 16)
                | (mask_octets[2] << 8)
                | mask_octets[3]
            )

            inverted_mask = (~mask_int) & 0xFFFFFFFF
            if (inverted_mask & (inverted_mask + 1)) != 0:
                raise ValueError(f"Маска подсети не является непрерывной: {prefix_str}")

            prefix_len = mask_int.bit_count()

    return IPInfo(4, address_int, prefix_len)


def _parse_ipv6(s: str) -> IPInfo:
    s = s.strip()

    prefix_len = None
    if "/" in s:
        s, prefix_str = s.split("/", 1)
        if not prefix_str.isdigit():
            raise ValueError(f"Префикс IPv6 должен быть числом: /{prefix_str}")
        prefix_len = int(prefix_str)
        if prefix_len < 0 or prefix_len > 128:
            raise ValueError(f"Префикс IPv6 должен быть 0-128, получено {prefix_len}")

    zone = None
    if "%" in s:
        idx = s.index("%")
        addr = s[:idx]
        zone = s[idx + 1 :]
        if not zone:
            raise ValueError("Пустая зона после '%'")
        if not re.match(r"^[A-Za-z0-9\-._~%]+$", zone):
            raise ValueError(f"Зона содержит недопустимые символы: {zone}")
        s = addr

    if "." in s.split(":")[-1]:
        parts = s.split(":")
        ipv4_part = parts[-1]
        ipv4_info = _parse_ipv4(ipv4_part)
        ipv4_address_int = ipv4_info.address_int
        high_group = (ipv4_address_int >> 16) & 0xFFFF
        low_group = ipv4_address_int & 0xFFFF
        parts[-1] = f"{high_group:x}:{low_group:x}"
        s = ":".join(parts)

    if ":::" in s:
        raise ValueError("IPv6 адрес не может содержать ':::'")

    if "::" in s:
        if s.count("::") > 1:
            raise ValueError(f"IPv6 адрес не может содержать более одного '::': {s}")
        left, right = s.split("::", 1)
        left_groups = left.split(":") if left else []
        right_groups = right.split(":") if right else []
        if "" in left_groups or "" in right_groups:
            raise ValueError(f"Некорректный формат IPv6 адреса: {s}")
        total_groups = len(left_groups) + len(right_groups)
        if total_groups > 7:
            raise ValueError(f"Слишком много групп в IPv6 адресе: {s}")
        missing = 8 - total_groups
        groups = left_groups + ["0"] * missing + right_groups
    else:
        groups = s.split(":")
        if len(groups) != 8:
            raise ValueError(
                f"IPv6 адрес без '::' должен содержать 8 групп, получено {len(groups)}"
            )

    for g in groups:
        if not re.match(r"^[0-9a-fA-F]{1,4}$", g):
            raise ValueError(f"Некорректная группа IPv6: '{g}'")

    group_ints = [int(g, 16) for g in groups]

    address_int = 0
    for val in group_ints:
        address_int = (address_int << 16) | val

    return IPInfo(6, address_int, prefix_len, zone)


# --------------------------------------------------------------
# Основные функции
# --------------------------------------------------------------


def parse_ip(ip_str: str) -> IPInfo:
    s = ip_str.strip()
    if ":" in s:
        return _parse_ipv6(s)
    else:
        return _parse_ipv4(s)


def parse_version_and_hex(ip_str: str) -> Tuple[int, str]:
    info = parse_ip(ip_str)
    return info.version, info.hex


def same_version(ip1_str: str, ip2_str: str) -> bool:
    v1 = parse_ip(ip1_str).version
    v2 = parse_ip(ip2_str).version
    return v1 == v2


def minimal_common_subnet(ip1_str: str, ip2_str: str) -> IPInfo:
    info1 = parse_ip(ip1_str)
    info2 = parse_ip(ip2_str)
    if info1.version != info2.version:
        raise ValueError(f"Адреса разных версий: {info1.version} vs {info2.version}")

    max_bits = info1.max_bits
    a = info1.address_int
    b = info2.address_int
    diff = a ^ b
    if diff == 0:
        prefix_len = max_bits
    else:
        prefix_len = max_bits - diff.bit_length()

    if prefix_len == 0:
        network_int = 0
    else:
        network_int = (a >> (max_bits - prefix_len)) << (max_bits - prefix_len)

    return IPInfo(info1.version, network_int, prefix_len)
