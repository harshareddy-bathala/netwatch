"""
formatters.py - Display Formatting Utilities
==============================================

Pure functions for formatting bandwidth rates and data totals.

CRITICAL DISTINCTION:
    format_bandwidth_rate() → For dashboard bandwidth card, chart Y-axis (RATE in Mbps)
    format_total_data()     → For device "Total Sent/Received" columns (CUMULATIVE in MB/GB)
"""


def format_bandwidth_rate(bytes_per_second: float) -> str:
    """
    Format bandwidth RATE for display.

    Input:  bytes per second (from packet capture / BandwidthCalculator)
    Output: Human-readable string with Mbps / Kbps / B/s

    CRITICAL: This is for RATE (bps), not total data transferred.

    Examples:
        375_000  → "3.0 Mbps"   (YouTube HD)
        12_500   → "100.0 Kbps" (light browsing)
        50       → "50 B/s"     (idle)
        0        → "0 B/s"
    """
    if bytes_per_second <= 0:
        return "0 B/s"

    # Convert bytes/sec → megabits/sec
    mbps = (bytes_per_second * 8) / 1_000_000

    if mbps >= 1.0:
        # >= 1 Mbps: Show as "X.X Mbps"
        return f"{mbps:.1f} Mbps"

    # Convert to kilobits/sec
    kbps = (bytes_per_second * 8) / 1_000

    if kbps >= 1.0:
        # >= 1 Kbps: Show as "XX.X Kbps"
        return f"{kbps:.1f} Kbps"

    # Show raw bytes/sec
    return f"{bytes_per_second:.0f} B/s"


def format_total_data(total_bytes: int) -> str:
    """
    Format total data transferred (cumulative).

    Input:  total bytes (sum of all packets)
    Output: Human-readable string with GB / MB / KB / B

    CRITICAL: This is for TOTAL data, not rate.

    Examples:
        1_500_000_000 → "1.50 GB"
        150_500_000   → "150.5 MB"
        45_200        → "45.2 KB"
        500           → "500 B"
    """
    if total_bytes is None or total_bytes < 0:
        total_bytes = 0

    if total_bytes >= 1_000_000_000:
        gb = total_bytes / 1_000_000_000
        return f"{gb:.2f} GB"
    elif total_bytes >= 1_000_000:
        mb = total_bytes / 1_000_000
        return f"{mb:.1f} MB"
    elif total_bytes >= 1_000:
        kb = total_bytes / 1_000
        return f"{kb:.1f} KB"
    else:
        return f"{total_bytes} B"


def bytes_to_mbps(bytes_per_second: float) -> float:
    """
    Convert bytes per second to megabits per second.

    Args:
        bytes_per_second: Raw bytes/second value

    Returns:
        Mbps as a float, rounded to 4 decimal places
    """
    if bytes_per_second <= 0:
        return 0.0
    return round((bytes_per_second * 8) / 1_000_000, 4)
