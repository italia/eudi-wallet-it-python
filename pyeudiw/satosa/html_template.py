from jinja2 import Environment, FileSystemLoader, select_autoescape


class Jinja2TemplateHandler:

    def __init__(self, config):
        config = config['ui']

        # error pages handler
        self.loader = Environment(
            loader=FileSystemLoader(searchpath=config["template_folder"]),
            autoescape=select_autoescape(["html"]),
        )
        _static_url = (
            config["static_storage_url"]
            if config["static_storage_url"][-1] == "/"
            else config["static_storage_url"] + "/"
        )
        self.loader.globals.update(
            {
                "static": _static_url,
            }
        )

        self.qrcode_page = self.loader.get_template(
            config["qrcode_template"]
        )

        # TODO - for rendering custom errors
        # self.error_page = self.loader.get_template(
        # config["error_template"]
        # )
