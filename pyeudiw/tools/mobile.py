from device_detector import DeviceDetector


def is_smartphone(useragent: str) -> bool:
    """Check if the useragent is a smartphone

    :param useragent: The useragent to check
    :type useragent: str
    :return: True if the useragent is a smartphone else False
    :rtype: bool
    """

    device = DeviceDetector(useragent).parse()
    if device.device_type() == "smartphone":
        return True
    return False
