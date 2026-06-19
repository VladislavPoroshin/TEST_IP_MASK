from ip_utils import (IPInfo, minimal_common_subnet, parse_ip,
                      parse_version_and_hex, same_version)

# ------------------------------------------------------------------------------
# Глобальные переменные
# ------------------------------------------------------------------------------


passed = 0
failed = 0


# ------------------------------------------------------------------------------
# Основные функции для тестирования
# ------------------------------------------------------------------------------


def test(name, condition, message=None):
    global passed, failed
    if condition:
        passed += 1
        print(f"[PASS] {name}")
    else:
        failed += 1
        print(f"[FAIL] {name}" + (f"  -> {message}" if message else ""))


def test_raises(name, exc_type, func, *args, **kwargs):
    global passed, failed
    try:
        func(*args, **kwargs)
        failed += 1
        print(
            f"[FAIL] {name}  -> ожидалось исключение {exc_type.__name__}, но оно не возникло"
        )
    except Exception as e:
        if isinstance(e, exc_type):
            passed += 1
            print(f"[PASS] {name}")
        else:
            failed += 1
            print(
                f"[FAIL] {name}  -> ожидалось {exc_type.__name__}, получено {type(e).__name__}: {e}"
            )


# ------------------------------------------------------------------------------
# Тесты парсинга IPv4 (позитивные)
# ------------------------------------------------------------------------------


def test_parse_ipv4_valid():

    info = parse_ip("192.168.1.1")
    test("IPv4 простой адрес", info.version == 4 and info.address_int == 0xC0A80101)

    info = parse_ip("10.0.0.1/24")
    test(
        "IPv4 с префиксом /24",
        info.version == 4 and info.address_int == 0x0A000001 and info.prefix_len == 24,
    )

    info = parse_ip("172.16.5.1/255.240.0.0")
    test(
        "IPv4 с маской 255.240.0.0",
        info.version == 4 and info.address_int == 0xAC100501 and info.prefix_len == 12,
    )

    info = parse_ip("1.1.1.1/0")
    test("IPv4 /0", info.prefix_len == 0)
    info = parse_ip("1.1.1.1/32")
    test("IPv4 /32", info.prefix_len == 32)

    info = parse_ip("0.0.0.0/0.0.0.0")
    test("IPv4 маска 0.0.0.0", info.prefix_len == 0)

    info = parse_ip("192.0.2.1")
    test("IPv4 октет с нулём", info.address_int == 0xC0000201)


# ------------------------------------------------------------------------------
# Тесты парсинга IPv4 (негативные)
# ------------------------------------------------------------------------------


def test_parse_ipv4_invalid():
    test_raises("IPv4 неверный формат (буквы)", ValueError, parse_ip, "192.168.a.1")
    test_raises("IPv4 октет >255", ValueError, parse_ip, "192.168.256.1")
    test_raises("IPv4 неполный адрес", ValueError, parse_ip, "192.168.1")
    test_raises("IPv4 префикс >32", ValueError, parse_ip, "10.0.0.1/33")
    test_raises(
        "IPv4 маска не непрерывна", ValueError, parse_ip, "10.0.0.1/255.0.255.0"
    )
    test_raises(
        "IPv4 маска не четыре октета", ValueError, parse_ip, "10.0.0.1/255.255.0"
    )
    test_raises("IPv4 отрицательный октет", ValueError, parse_ip, "192.168.-1.1")
    test_raises("IPv4 маска с буквами", ValueError, parse_ip, "10.0.0.1/255.255.ff.0")
    test_raises(
        "IPv4 маска с отрицательным октетом",
        ValueError,
        parse_ip,
        "10.0.0.1/255.255.-1.0",
    )


# ------------------------------------------------------------------------------
# Тесты парсинга IPv6 (позитивные)
# ------------------------------------------------------------------------------


def test_parse_ipv6_valid():

    info = parse_ip("::1")
    test(
        "IPv6 петлевой адрес",
        info.version == 6 and info.address_int == 1 and info.prefix_len is None,
    )

    info = parse_ip("fe80::1%eth0")
    test(
        "IPv6 link-local с зоной",
        info.version == 6
        and info.zone == "eth0"
        and info.address_int == 0xFE800000000000000000000000000001,
    )

    info = parse_ip("2001:db8::1/64")
    test(
        "IPv6 с префиксом /64",
        info.version == 6
        and info.prefix_len == 64
        and info.address_int == 0x20010DB8000000000000000000000001,
    )

    info = parse_ip("::ffff:192.168.1.1")
    test(
        "IPv6 mapped IPv4",
        info.address_int == 0x00000000000000000000FFFFC0A80101,
    )

    info = parse_ip("::192.168.1.1")
    test(
        "IPv6 compatible IPv4",
        info.address_int == 0x000000000000000000000000C0A80101,
    )

    info = parse_ip("fe80::5efe:192.168.1.1")
    test(
        "IPv6 ISATAP",
        info.address_int == 0xFE8000000000000000005EFEC0A80101 and info.zone is None,
    )

    info = parse_ip("64:ff9b::192.168.1.1")
    test(
        "IPv6 NAT64 WKP",
        info.address_int == 0x0064FF9B0000000000000000C0A80101,
    )

    info = parse_ip("::2")
    test("IPv6 сжатый ::2", info.address_int == 2)

    info = parse_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    test(
        "IPv6 полный",
        info.address_int == 0x20010DB885A3000000008A2E03707334,
    )

    info = parse_ip("fe80::192.168.1.1")
    test(
        "IPv6 со встроенным IPv4",
        info.address_int == 0xFE8000000000000000000000C0A80101,
    )


# ------------------------------------------------------------------------------
# Тесты парсинга IPv6 (негативные)
# ------------------------------------------------------------------------------


def test_parse_ipv6_invalid():
    test_raises("IPv6 два ::", ValueError, parse_ip, "2001::db8::1")
    test_raises("IPv6 тройное двоеточие :::", ValueError, parse_ip, "2001:::1")
    test_raises("IPv6 слишком много групп", ValueError, parse_ip, "1:2:3:4:5:6:7:8:9")
    test_raises("IPv6 недостаточно групп без ::", ValueError, parse_ip, "1:2:3:4:5:6:7")
    test_raises(
        "IPv6 недопустимые символы в группе", ValueError, parse_ip, "fe80::gggg"
    )
    test_raises("IPv6 префикс >128", ValueError, parse_ip, "::1/129")
    test_raises("IPv6 префикс не число", ValueError, parse_ip, "::1/abc")
    test_raises(
        "IPv6 зона с двоеточием",
        ValueError,
        parse_ip,
        "fe80::1%eth:0",
    )
    test_raises(
        "IPv6 пустая зона",
        ValueError,
        parse_ip,
        "fe80::1%",
    )
    test_raises("IPv6 отрицательный октет", ValueError, parse_ip, "2001::db8:-1")
    test_raises(
        "IPv6 маска с отрицательным октетом", ValueError, parse_ip, "2001::db8:1/-1"
    )


# ------------------------------------------------------------------------------
# Тесты parse_version_and_hex
# ------------------------------------------------------------------------------


def test_parse_version_and_hex():
    ver, hx = parse_version_and_hex("192.168.1.1")
    test("parse_version_and_hex IPv4", ver == 4 and hx == "C0A80101")
    ver, hx = parse_version_and_hex("::1")
    test(
        "parse_version_and_hex IPv6",
        ver == 6 and hx == "00000000000000000000000000000001",
    )


# ------------------------------------------------------------------------------
# Тесты same_version
# ------------------------------------------------------------------------------


def test_same_version_func():
    test("same_version IPv4", same_version("192.168.1.1", "10.0.0.1") == True)
    test("same_version IPv6", same_version("::1", "fe80::1") == True)
    test("same_version IPv4 + IPv6", same_version("1.1.1.1", "::1") == False)
    test("same_version IPv6 + IPv4", same_version("::1", "1.1.1.1") == False)


# ------------------------------------------------------------------------------
# Тесты minimal_common_subnet
# ------------------------------------------------------------------------------


def test_minimal_common_subnet():

    net = minimal_common_subnet("192.168.1.1", "192.168.2.1")
    test(
        "Подсеть 192.168.1.1 + 192.168.2.1",
        net.version == 4 and net.address_int == 0xC0A80000 and net.prefix_len == 22,
    )

    net = minimal_common_subnet("10.0.0.1", "10.0.0.15")
    test(
        "Подсеть 10.0.0.1 + 10.0.0.15",
        net.address_int == 0x0A000000 and net.prefix_len == 28,
    )

    net = minimal_common_subnet("1.1.1.1", "255.255.255.255")
    test(
        "Подсеть 1.1.1.1 + 255.255.255.255",
        net.prefix_len == 0 and net.address_int == 0,
    )

    net = minimal_common_subnet("fe80::1", "fe80::2")
    test(
        "Подсеть fe80::1 + fe80::2",
        net.version == 6
        and net.address_int == 0xFE800000000000000000000000000000
        and net.prefix_len == 126,
    )

    net = minimal_common_subnet("::1:1", "::2:1")
    test(
        "Подсеть ::1:1 + ::2:1",
        net.address_int == 0 and net.prefix_len == 110,
    )

    test_raises(
        "Подсеть разных версий",
        ValueError,
        minimal_common_subnet,
        "192.168.1.1",
        "::1",
    )


# ------------------------------------------------------------------------------
# Тесты форматирования IPInfo
# ------------------------------------------------------------------------------


def test_formatting():

    info = IPInfo(4, 0xC0A80101, prefix_len=24)
    test("IPv4 to_string", info.to_string() == "192.168.1.1")
    test(
        "IPv4 to_string with_prefix",
        info.to_string(with_prefix=True) == "192.168.1.1/24",
    )
    test("IPv4 __str__", str(info) == "192.168.1.1/24")
    test("IPv4 to_netmask", info.to_netmask() == "255.255.255.0")
    test("IPv4 hex", info.hex == "C0A80101")

    info = IPInfo(6, 0x20010DB8000000000000000000000001, prefix_len=64)
    test("IPv6 to_string", info.to_string() == "2001:db8::1")
    test(
        "IPv6 to_string with_prefix",
        info.to_string(with_prefix=True) == "2001:db8::1/64",
    )
    test("IPv6 __str__", str(info) == "2001:db8::1/64")
    test("IPv6 to_netmask", info.to_netmask() == "ffff:ffff:ffff:ffff::")
    test(
        "IPv6 hex",
        info.hex == "20010DB8000000000000000000000001",
    )

    test_raises(
        "to_netmask без префикса",
        ValueError,
        IPInfo(4, 0).to_netmask,
    )


# ------------------------------------------------------------------------------
# Общий запуск
# ------------------------------------------------------------------------------


if __name__ == "__main__":
    print("=== Запуск тестов ip_utils ===\n")

    test_parse_ipv4_valid()
    test_parse_ipv4_invalid()
    test_parse_ipv6_valid()
    test_parse_ipv6_invalid()
    test_parse_version_and_hex()
    test_same_version_func()
    test_minimal_common_subnet()
    test_formatting()

    print(f"\n=== Итого: {passed} прошло, {failed} упало ===")
