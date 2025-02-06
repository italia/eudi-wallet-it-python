from satosa.context import Context

from pyeudiw.satosa.exceptions import EmptyHTTPError
from pyeudiw.satosa.utils.response import JsonResponse
from pyeudiw.tools.base_logger import BaseLogger


class BaseHTTPErrorHandler(BaseLogger):
    def _serialize_error(
        self,
        context: Context,
        message: str,
        troubleshoot: str,
        err: str,
        err_code: str,
        level: str,
    ) -> JsonResponse:
        """
        Serializes an error.

        :param context: the request context
        :type context: satosa.context.Context
        :param message: the error message
        :type message: str
        :param troubleshoot: the troubleshoot message
        :type troubleshoot: str
        :param err: more info about the error
        :type err: str
        :param err_code: the error code
        :type err_code: str
        :param level: the log level
        :type level: str

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        _msg = f"{message}:"
        if err:
            _msg += f" {err}."
        self._log(context, level=level, message=f"{_msg} {troubleshoot}")

        return JsonResponse(
            {"error": message, "error_description": troubleshoot}, status=err_code
        )

    def _handle_500(self, context: Context, msg: str, err: Exception) -> JsonResponse:
        """
        Handles a 500 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param msg: the error message
        :type msg: str
        :param err: the exception raised
        :type err: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._serialize_error(
            context,
            "server_error",
            f"{msg}",
            f"{msg}. {err.__class__.__name__}: {err}",
            "500",
            "error",
        )

    def _handle_40X(
        self,
        code_number: str,
        message: str,
        context: Context,
        troubleshoot: str,
        err: Exception,
    ) -> JsonResponse:
        """
        Handles a 40X error.

        :param code_number: the code number
        :type code_number: str
        :param message: the error message
        :type message: str
        :param context: the request context
        :type context: satosa.context.Context
        :param troubleshoot: the troubleshoot message
        :type troubleshoot: str
        :param err: the exception raised
        :type err: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._serialize_error(
            context,
            message,
            troubleshoot,
            f"{err.__class__.__name__}: {err}",
            f"40{code_number}",
            "error",
        )

    def _handle_400(
        self, context: Context, troubleshoot: str, err: Exception = EmptyHTTPError("")
    ) -> JsonResponse:
        """
        Handles a 400 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param troubleshoot: the troubleshoot message
        :type troubleshoot: str
        :param err: the exception raised
        :type err: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """
        return self._handle_40X("0", "invalid_request", context, troubleshoot, err)

    def _handle_401(
        self, context, troubleshoot: str, err: EmptyHTTPError = EmptyHTTPError("")
    ):
        """
        Handles a 401 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param troubleshoot: the troubleshoot message
        :type troubleshoot: str
        :param err: the exception raised
        :type err: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._handle_40X("1", "invalid_client", context, troubleshoot, err)

    def _handle_403(
        self, context, troubleshoot: str, err: EmptyHTTPError = EmptyHTTPError("")
    ):
        """
        Handles a 403 error.

        :param context: the request context
        :type context: satosa.context.Context
        :param troubleshoot: the troubleshoot message
        :type troubleshoot: str
        :param err: the exception raised
        :type err: Exception

        :return: a json response containing the error
        :rtype: JsonResponse
        """

        return self._handle_40X("3", "expired", context, troubleshoot, err)
