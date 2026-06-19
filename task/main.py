import sys

from ip_utils import minimal_common_subnet, parse_ip


def main():
    print("=== Вычисление минимальной общей подсети для двух IP-адресов ===\n")

    try:
        ip_str1 = input("Введите первый IP-адрес: ").strip()
        ip_str2 = input("Введите второй IP-адрес: ").strip()
    except KeyboardInterrupt:
        print("\nОтмена.")
        sys.exit(0)

    try:
        info1 = parse_ip(ip_str1)
        info2 = parse_ip(ip_str2)
    except ValueError as e:
        print(f"Ошибка при разборе адреса: {e}")
        sys.exit(1)

    if info1.version != info2.version:
        print(
            f"Адреса разных версий (IPv{info1.version} и IPv{info2.version}). "
            "Общая подсеть невозможна."
        )
        sys.exit(1)

    try:
        subnet = minimal_common_subnet(ip_str1, ip_str2)
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)

    print("\nРезультат:")
    print(f"  Версия протокола:      IPv{subnet.version}")
    print(f"  Адрес сети:            {subnet.to_string()}")
    print(f"  Длина префикса (CIDR): /{subnet.prefix_len}")
    print(f"  Маска подсети:         {subnet.to_netmask()}")
    print(f"  Hex представление сети: {subnet.hex}")


if __name__ == "__main__":
    main()
