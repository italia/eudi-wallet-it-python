from device_detector import DeviceDetector


def is_smartphone(useragent: str):
    device = DeviceDetector(useragent).parse()
    if device.device_type() == 'smartphone':
        return True
