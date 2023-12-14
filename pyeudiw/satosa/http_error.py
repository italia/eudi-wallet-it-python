import logging
from pyeudiw.satosa.response import JsonResponse

logger = logging.getLogger(__name__)

class HTTPErrorHandler:
    def __init__(self, template_path: str, error_template: str, log):
        self.template_path = template_path
        self.error_template = error_template
        self._log = log

    def _serialize_error(
            self,
            context, 
            message: str,
            troubleshoot: str, 
            err: str, 
            err_code: str, 
            level: str
    ):
        _msg = f"{message}:"
        if err:
            _msg += f" {err}."
        self._log(
            context, level=level,
            message=f"{_msg} {troubleshoot}"
        )

        return JsonResponse(
            {
                "error": message,
                "error_description": troubleshoot
            },
            status=err_code
        )

    def handle500(self, context, troubleshoot: str = "", err: str = ""):
        return self._serialize_error(context, "server_error", troubleshoot, err, "500", "error")
    
    def handle40X(self, code_number: str, message: str, context, troubleshoot: str = "", err: str = ""):
        return self._serialize_error(context, message, troubleshoot, err, f"40{code_number}", "error")